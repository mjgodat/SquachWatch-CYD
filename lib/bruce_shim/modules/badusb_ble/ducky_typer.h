// Bruce shim — modules/badusb_ble/ducky_typer.h
// Minimal stub for BLE modules that reference HID cleanup
#pragma once
#include <Arduino.h>

// HIDInterface stub — Bruce's BLE spam modules check/clean these up
struct HIDInterface {
    virtual ~HIDInterface() {}
};

extern HIDInterface *hid_usb;
extern HIDInterface *hid_ble;
extern int activeBLEInstances;

// Stubs — real implementations would go here for full BadUSB support
inline void ducky_setup(HIDInterface *&hid, bool ble = false) { (void)hid; (void)ble; }
inline void cleanupDuckyBLE(HIDInterface *&hid) {
    if (hid) { delete hid; hid = nullptr; }
}
inline void safeCleanupDuckyBLE(HIDInterface *&hid) { cleanupDuckyBLE(hid); }
