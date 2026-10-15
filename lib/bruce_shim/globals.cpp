// Bruce shim — globals.cpp
#include "globals.h"
#include "modules/badusb_ble/ducky_typer.h"

TFT_eSPI* bruce_tft = nullptr;
BruceConfig bruceConfig;
BruceConfigPins bruceConfigPins;
volatile bool AnyKeyPress = false;
volatile bool EscPress = false;
volatile bool SelPress = false;
volatile bool PrevPress = false;
volatile bool NextPress = false;
volatile bool returnToMenu = false;
TouchPoint touchPoint;

// HID stubs
HIDInterface *hid_usb = nullptr;
HIDInterface *hid_ble = nullptr;
int activeBLEInstances = 0;
