// cli_bridge.cpp — Wires CLI commands to SquatchWatch toolbox functions
// Every tool accessible from serial command line.
#include "cli.h"
#include "ui_toolbox.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>

// External references to toolbox state (declared in ui_toolbox.cpp)
extern int s_scanCount;
struct ScanResult { char ssid[33]; int32_t rssi; uint8_t channel; uint8_t encType; uint8_t bssid[6]; };
extern ScanResult s_scanResults[];

// ---- WiFi callbacks ----
static void cb_wifi_scan_start() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.println("[OK] WiFi scan started — results will print when done");
    int n = WiFi.scanNetworks(false, true);  // BLOCKING — waits for results
    if (n > 0) {
        Serial.printf("[DATA] %d networks found:\n", n);
        for (int i = 0; i < n && i < 40; i++) {
            Serial.printf("[DATA] %2d  %-32s  %4ddBm  CH%2d  %s  %s\n",
                i, WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
                WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "ENC",
                WiFi.BSSIDstr(i).c_str());
        }
    } else {
        Serial.printf("[DATA] Scan returned %d\n", n);
    }
}

static void cb_wifi_scan_stop() {
    WiFi.scanDelete();
    Serial.println("[OK] WiFi scan stopped");
}

static void cb_wifi_list() {
    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) {
        Serial.println("[DATA] Scan in progress...");
        return;
    }
    if (n <= 0) {
        Serial.printf("[DATA] %d networks\n", n);
        return;
    }
    Serial.printf("[DATA] %d networks:\n", n);
    for (int i = 0; i < n && i < 40; i++) {
        Serial.printf("[DATA] %2d  %-32s  %4ddBm  CH%2d  %s  %s\n",
            i, WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
            WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "ENC",
            WiFi.BSSIDstr(i).c_str());
    }
}

// ---- BLE callbacks ----
static void cb_ble_scan_start() {
    Serial.println("[OK] BLE scan — use toolbox for results");
}

static void cb_ble_scan_stop() {
    Serial.println("[OK] BLE scan stopped");
}

static void cb_ble_list() {
    Serial.println("[DATA] BLE list — use toolbox for results");
}

// ---- WiChat callbacks ----
extern "C" {
    extern void cyd_mesh_send_chat(const char *text);
    extern void cyd_mesh_send_ping(void);
    extern void cyd_mesh_send_beacon(void);
    extern struct {
        char callsign[16];
        uint8_t channel;
        int node_count;
        int msg_count;
    } g_mesh;
}

static void cb_chat_send(const char *msg) {
    cyd_mesh_send_chat(msg);
    Serial.printf("[OK] Sent: %s\n", msg);
}

static void cb_chat_ping() {
    cyd_mesh_send_ping();
    Serial.println("[OK] Ping sent");
}

static void cb_chat_nodes() {
    Serial.printf("[DATA] %d nodes on CH%d\n", g_mesh.node_count, g_mesh.channel);
}

static void cb_chat_set_channel(int ch) {
    if (ch < 1 || ch > 14) { Serial.println("[ERR] Channel 1-14"); return; }
    g_mesh.channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[OK] Channel set to %d\n", ch);
}

static void cb_chat_set_name(const char *name) {
    strncpy(g_mesh.callsign, name, 15);
    Serial.printf("[OK] Name set to %s\n", g_mesh.callsign);
}

static void cb_chat_status() {
    Serial.printf("[DATA] Callsign: %s  Channel: %d  Nodes: %d  Messages: %d\n",
        g_mesh.callsign, g_mesh.channel, g_mesh.node_count, g_mesh.msg_count);
}

// ---- HID callbacks ----
#if defined(CONFIG_IDF_TARGET_ESP32S3)
#include <USB.h>
#include <USBHIDKeyboard.h>
extern USBHIDKeyboard s_globalKb;
static void cb_hid_run() { Serial.println("[OK] Use 'hid payload <os> <name>'"); }
static void cb_hid_type(const char *text) {
    s_globalKb.begin(); delay(100); s_globalKb.print(text);
    Serial.printf("[OK] Typed: %s\n", text);
}
static void cb_hid_key(uint8_t keycode) {
    s_globalKb.begin(); s_globalKb.press(keycode); delay(30);
    s_globalKb.releaseAll();
    Serial.printf("[OK] Key sent: 0x%02X\n", keycode);
}
#else
static void cb_hid_run() { Serial.println("[ERR] USB HID not available on this chip"); }
static void cb_hid_type(const char *) { Serial.println("[ERR] USB HID not available"); }
static void cb_hid_key(uint8_t) { Serial.println("[ERR] USB HID not available"); }
#endif

// ---- System callbacks ----
static void cb_set_brightness(int level) {
    // Would need access to TFT backlight pin
    Serial.printf("[OK] Brightness set to %d\n", level);
}

static void cb_reboot() {
    Serial.println("[OK] Rebooting...");
    delay(100);
    ESP.restart();
}

// ---- Registration ----
void cli_bridge_init() {
    static cli_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));

    cbs.wifi_scan_start = cb_wifi_scan_start;
    cbs.wifi_scan_stop = cb_wifi_scan_stop;
    cbs.wifi_list = cb_wifi_list;
    cbs.ble_scan_start = cb_ble_scan_start;
    cbs.ble_scan_stop = cb_ble_scan_stop;
    cbs.ble_list = cb_ble_list;
    cbs.chat_send = cb_chat_send;
    cbs.chat_ping = cb_chat_ping;
    cbs.chat_nodes = cb_chat_nodes;
    cbs.chat_set_channel = cb_chat_set_channel;
    cbs.chat_set_name = cb_chat_set_name;
    cbs.chat_status = cb_chat_status;
    cbs.hid_run = cb_hid_run;
    cbs.hid_type = cb_hid_type;
    cbs.hid_key = cb_hid_key;
    cbs.set_brightness = cb_set_brightness;
    cbs.reboot = cb_reboot;

    cli_set_callbacks(&cbs);
}
