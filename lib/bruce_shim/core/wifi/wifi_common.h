// Bruce shim — core/wifi/wifi_common.h
#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <LittleFS.h>

#define WIFI_ATK_NAME "BruceAP"

inline bool wifiConnected() { return WiFi.isConnected(); }
inline void cleanlyStopWebUiForWiFiFeature() {}
inline void ensureWifiPlatform() {}
inline bool checkLittleFsSize(size_t) { return true; }
inline bool checkLittleFsSizeNM(size_t) { return true; }
