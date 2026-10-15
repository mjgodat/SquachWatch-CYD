// Bruce shim — globals.h
// Maps Bruce's global state to SquatchWatch's environment.
#pragma once
#include <Arduino.h>
#include <TFT_eSPI.h>

// Forward declare the SquatchWatch canvas that Bruce modules draw to
extern TFT_eSPI* bruce_tft;

// Shim: Bruce modules use `tft.` — we provide a reference
#define tft (*bruce_tft)

// Screen dimensions (landscape 480x320)
#define tftWidth  (bruce_tft->width())
#define tftHeight (bruce_tft->height())
#define WIDTH     tftWidth
#define HEIGHT    tftHeight

// Font sizes Bruce uses
#ifndef FP
#define FP 1
#endif
#ifndef FM
#define FM 2
#endif
#ifndef FG
#define FG 3
#endif

// Bruce config stub
struct BruceConfigWifiAp {
    String ssid = "BruceAP";
    String pwd = "";
};

struct EvilPortalEndpoints {
    bool allowGetCreds = true;
    bool allowSetSsid = true;
    bool showEndpoints = true;
    String getCredsEndpoint = "/get-creds";
    String setSsidEndpoint = "/set-ssid";
};

struct BruceConfig {
    uint16_t priColor = 0x07FF;   // cyan
    uint16_t bgColor  = 0x0000;   // black
    uint16_t secColor = 0xF800;   // red
    BruceConfigWifiAp wifiAp;
    EvilPortalEndpoints evilPortalEndpoints;
    String evilPortalGatewayIp = "172.0.0.1";
    std::vector<String> evilWifiNames;

    String getWifiPassword(const String&) { return ""; }
    void addWifiCredential(const String&, const String&) {}
};

struct BruceConfigPins {
    uint8_t rotation = 1;
};

extern BruceConfig bruceConfig;
extern BruceConfigPins bruceConfigPins;

// Input state — mapped from SquatchWatch touch in the toolbox tick
extern volatile bool AnyKeyPress;
extern volatile bool EscPress;
extern volatile bool SelPress;
extern volatile bool returnToMenu;

// check() macro Bruce uses
inline bool check(volatile bool& flag) {
    bool v = flag;
    flag = false;
    return v;
}

// Keyboard stub
struct TouchPoint {
    int16_t x = 0, y = 0;
    bool pressed = false;
};
extern TouchPoint touchPoint;

// Color helper Bruce uses
inline uint16_t getColorVariation(uint16_t color) { return color; }
