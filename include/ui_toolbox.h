// SquachWatch-CYD — Bruce Toolbox
// Offensive tools menu: WiFi attacks, BLE spam, BadUSB payloads.
// Layer 2 of the two-layer system: SquatchWatch is the OS, these are the apps.
#pragma once
#include <TFT_eSPI.h>

enum class ToolCategory : uint8_t {
    WIFI = 0,
    BLE,
    USB,
    UTIL,
    BACK,
    COUNT
};

enum class WifiTool : uint8_t {
    SCAN_NETWORKS = 0,
    DEAUTH,
    BEACON_SPAM,
    EVIL_PORTAL,
    PROBE_SNIFF,
    PMKID_CAPTURE,
    HANDSHAKE_CAPTURE,
    PCAP_CAPTURE,
    DHCP_STARVE,
    AP_CLONE,
    KARMA,
    RICKROLL,
    BACK,
    COUNT
};

enum class BleTool : uint8_t {
    SCAN_DEVICES = 0,
    APPLE_SPAM,
    SAMSUNG_SPAM,
    SWIFTPAIR_SPAM,
    AIRTAG_SPOOF,
    FLIPPER_DETECT,
    BLE_ENUM,
    BACK,
    COUNT
};

enum class UsbTool : uint8_t {
    DUCKY_SCRIPT = 0,   // load from SD
    KEYSTROKE_INJECT,
    USB_KEYBOARD,
    USB_STORAGE,
    BACK,
    COUNT
};

enum class UtilTool : uint8_t {
    SD_BROWSER = 0,
    WIFI_LOGGER,
    PCAP_VIEWER,
    BACK,
    COUNT
};

// Which level of the toolbox menu we are in
enum class ToolboxLevel : uint8_t {
    CATEGORIES = 0,   // top level: WiFi / BLE / USB / Util / Back
    WIFI_TOOLS,
    BLE_TOOLS,
    USB_TOOLS,
    UTIL_TOOLS,
    TOOL_RUNNING       // a tool is actively executing
};

void uiToolboxInit(TFT_eSPI& t);
void uiToolboxTick(TFT_eSPI& t, uint32_t now);
void uiToolboxScroll(int delta);

// Returns true if the toolbox wants to stay open; false means go back to CLEAR.
bool uiToolboxHandleTap(TFT_eSPI& t, int16_t x, int16_t y, uint32_t now);

// Returns true while a tool is running and owns the radio.
bool uiToolboxToolRunning();

// Stop whatever tool is running (called when leaving TOOLBOX state).
void uiToolboxStopTool();
