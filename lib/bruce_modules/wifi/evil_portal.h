// Stub — evil_portal.h (using SquatchWatch's own implementation)
#pragma once
#include <Arduino.h>

struct HandshakeCapture {
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t pmkid[16];
    bool hasPmkid;
    bool hasHandshake;
    String ssid;
};
