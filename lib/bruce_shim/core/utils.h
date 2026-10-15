// Bruce shim — core/utils.h
#pragma once
#include <Arduino.h>

inline String padString(const String &s, int len) {
    String r = s;
    while ((int)r.length() < len) r += " ";
    return r;
}
