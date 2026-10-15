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

// Option struct for loopOptions
struct Option {
    String label;
    std::function<void()> callback = nullptr;
    bool selected = false;
};

int loopOptions(std::vector<Option> &options, int type, const String &title, int index, bool locked);

inline int loopOptions(std::vector<Option> &options, int _index) {
    return loopOptions(options, 0, "", _index, false);
}
inline int loopOptions(std::vector<Option> &options) {
    return loopOptions(options, 0, "", 0, false);
}

void wifiDisconnect();
