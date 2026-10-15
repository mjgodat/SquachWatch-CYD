// Bruce shim — core/wifi/wifi_common.h
#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>

#define WIFI_ATK_NAME "BruceAP"

inline bool wifiConnected() { return WiFi.isConnected(); }
