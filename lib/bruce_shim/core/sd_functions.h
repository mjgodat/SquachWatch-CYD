// Bruce shim — core/sd_functions.h
#pragma once
#include <Arduino.h>
#include <FS.h>
#include <SD.h>

// Minimal stubs — expand as modules need SD access
inline bool setupSdCard() { return SD.begin(); }
