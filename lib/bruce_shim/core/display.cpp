// Bruce shim — core/display.cpp
#include "display.h"
#include <WiFi.h>

void displayRedStripe(const String &text, uint16_t fgcolor, uint16_t bgcolor) {
    if (!bruce_tft) return;
    int w = bruce_tft->width(), h = bruce_tft->height();
    int stripeH = 30;
    int y = h / 2 - stripeH / 2;
    bruce_tft->fillRect(0, y, w, stripeH, bgcolor);
    bruce_tft->setTextColor(fgcolor, bgcolor);
    bruce_tft->setTextDatum(MC_DATUM);
    bruce_tft->drawString(text, w / 2, y + stripeH / 2, 2);
}

void displayError(const String &txt, bool waitKeyPress) {
    displayRedStripe(txt, TFT_WHITE, TFT_RED);
    if (waitKeyPress) delay(2000);
}

void displayInfo(const String &txt, bool waitKeyPress) {
    displayRedStripe(txt, TFT_WHITE, TFT_BLUE);
    if (waitKeyPress) delay(1500);
}

void displayWarning(const String &txt, bool waitKeyPress) {
    displayRedStripe(txt, TFT_BLACK, TFT_YELLOW);
    if (waitKeyPress) delay(1500);
}

void displaySuccess(const String &txt, bool waitKeyPress) {
    displayRedStripe(txt, TFT_WHITE, TFT_DARKGREEN);
    if (waitKeyPress) delay(1500);
}

void drawMainBorder(bool clear) {
    if (!bruce_tft) return;
    int w = bruce_tft->width(), h = bruce_tft->height();
    if (clear) bruce_tft->fillScreen(bruceConfig.bgColor);
    bruce_tft->drawRect(2, 2, w - 4, h - 4, bruceConfig.priColor);
}

void drawMainBorderWithTitle(const String &title, bool clear) {
    drawMainBorder(clear);
    if (!bruce_tft) return;
    int w = bruce_tft->width();
    bruce_tft->fillRect(0, 0, w, STATUS_BAR_HEIGHT, bruceConfig.bgColor);
    bruce_tft->setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    bruce_tft->setTextDatum(MC_DATUM);
    bruce_tft->drawString(title, w / 2, STATUS_BAR_HEIGHT / 2, 2);
    bruce_tft->drawFastHLine(0, STATUS_BAR_HEIGHT, w, bruceConfig.priColor);
}

void padprint(const String &text, bool newline) {
    if (!bruce_tft) return;
    if (newline) {
        bruce_tft->println(text);
    } else {
        bruce_tft->print(text);
    }
}

int loopOptions(std::vector<Option> &options, int type, const String &title, int index, bool locked) {
    // Simplified: just return the index. Full implementation needs touch-based selection.
    // For now, Bruce modules that use loopOptions will need the toolbox menu to handle selection.
    return index;
}

void wifiDisconnect() {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
}
