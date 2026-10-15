// Bruce shim — core/display.h
// Maps Bruce's display helper functions to SquatchWatch's TFT_eSPI.
#pragma once
#include "globals.h"

#define STATUS_BAR_HEIGHT 30
#define BORDER_OFFSET_FROM_SCREEN_EDGE 5
#define BORDER_PAD_X 10
#define BORDER_PAD_Y 28

// Display helpers that Bruce modules call
void displayRedStripe(const String &text, uint16_t fgcolor = TFT_WHITE, uint16_t bgcolor = TFT_RED);
void displayError(const String &txt, bool waitKeyPress = false);
void displayInfo(const String &txt, bool waitKeyPress = false);
void displayWarning(const String &txt, bool waitKeyPress = false);
void displaySuccess(const String &txt, bool waitKeyPress = false);
void drawMainBorder(bool clear = true);
void drawMainBorderWithTitle(const String &title, bool clear = true);
void padprint(const String &text, bool newline = true);

// Option struct for loopOptions (matches Bruce's globals.h)
struct Option {
    String label;
    std::function<void()> operation;
    bool selected = false;
    bool enabled = true;

    Option(const char *lbl, const std::function<void()> &op, bool sel = false, bool en = true)
        : label(lbl), operation(op), selected(sel), enabled(en) {}
    Option() : selected(false), enabled(true) {}
};

int loopOptions(std::vector<Option> &options, int type, const String &title, int index, bool locked);

inline int loopOptions(std::vector<Option> &options, int _index) {
    return loopOptions(options, 0, "", _index, false);
}
inline int loopOptions(std::vector<Option> &options) {
    return loopOptions(options, 0, "", 0, false);
}

void wifiDisconnect();

// Menu helpers Bruce modules use
#define MENU_TYPE_MAIN 0
#define MENU_TYPE_SUBMENU 1
#define MENU_TYPE_REGULAR 2

inline void addOptionToMainMenu(const String&, std::function<void()>) {}
inline void displayTextLine(const String &text, int line = 0) {
    if (bruce_tft) {
        bruce_tft->setTextDatum(TL_DATUM);
        bruce_tft->drawString(text, 10, 40 + line * 16, 2);
    }
}

// Raw WiFi TX wrapper
#include <esp_wifi.h>
inline esp_err_t wifiRawTx(const void* buf, int len) {
    return esp_wifi_80211_tx(WIFI_IF_STA, buf, len, false);
}
