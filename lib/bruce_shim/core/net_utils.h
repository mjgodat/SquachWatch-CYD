// Bruce shim — core/net_utils.h
#pragma once
#include <Arduino.h>

inline String macToString(const uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

// Bruce uses MAC() as a function returning String from uint8_t[6]
inline String MAC(const uint8_t *data) { return macToString(data); }

inline void stringToMAC(const std::string &macStr, uint8_t mac[6]) {
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

inline String ipToString(const IPAddress &ip) { return ip.toString(); }
