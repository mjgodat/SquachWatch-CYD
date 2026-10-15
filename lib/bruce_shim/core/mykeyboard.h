// Bruce shim — core/mykeyboard.h
// Maps Bruce's input checks to SquatchWatch touch state.
#pragma once
#include "globals.h"

inline bool checkSelPress()  { return check(SelPress); }
inline bool checkEscPress()  { return check(EscPress); }
inline bool checkAnyKeyPress() { return check(AnyKeyPress); }

// Touch handling stubs
inline void touchHeatMap(TouchPoint &tp) { (void)tp; }

// Text input stub — Bruce's on-screen keyboard
inline String keyboard(const String &defaultText = "", int maxLen = 32, const String &title = "") {
    (void)maxLen; (void)title;
    return defaultText;
}
