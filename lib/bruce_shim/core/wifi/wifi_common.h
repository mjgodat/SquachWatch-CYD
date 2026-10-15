// Bruce shim — core/wifi/wifi_common.h
#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <LittleFS.h>

#define WIFI_ATK_NAME "BruceAP"

// Bruce uses wifiConnected as both a variable and function in different modules
extern bool wifiConnected;
extern String wifiIP;

inline void cleanlyStopWebUiForWiFiFeature() {}
inline void ensureWifiPlatform() { WiFi.mode(WIFI_STA); }
inline bool checkLittleFsSize(size_t needed = 0) { (void)needed; return true; }
inline bool checkLittleFsSizeNM(size_t needed = 0, bool silent = false) { (void)needed; (void)silent; return true; }
inline void drawStatusBar() {}
inline void drawStatusBar(bool) {}
