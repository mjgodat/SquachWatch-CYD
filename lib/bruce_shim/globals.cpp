// Bruce shim — globals.cpp
#include "globals.h"

TFT_eSPI* bruce_tft = nullptr;
BruceConfig bruceConfig;
BruceConfigPins bruceConfigPins;
volatile bool AnyKeyPress = false;
volatile bool EscPress = false;
volatile bool SelPress = false;
volatile bool returnToMenu = false;
TouchPoint touchPoint;
