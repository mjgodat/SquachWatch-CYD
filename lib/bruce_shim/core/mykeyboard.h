// Bruce shim — core/mykeyboard.h
// Maps Bruce's input checks to SquatchWatch touch state.
#pragma once
#include "globals.h"

inline bool checkSelPress()  { return check(SelPress); }
inline bool checkEscPress()  { return check(EscPress); }
inline bool checkAnyKeyPress() { return check(AnyKeyPress); }

// Touch handling stubs
void touchHeatMap(TouchPoint &tp);
inline void touchHeatMap(TouchPoint &tp) { (void)tp; }
