// wichat_hook.h — WiChat packet hook for SquatchWatch's promiscuous callback
// Called from detection.cpp's promiscuous RX callback for every frame.
// WiChat filters by BSSID and queues matching frames.
#pragma once
#include <stdint.h>
#include <esp_wifi.h>

#ifdef __cplusplus
extern "C" {
#endif

// Called from the promiscuous callback for every received frame.
// WiChat checks for its BSSID and queues matching frames.
typedef void (*wichat_rx_hook_t)(const wifi_promiscuous_pkt_t* pkt, uint16_t len);

// Set/clear the hook. Only one hook at a time.
void wichat_set_rx_hook(wichat_rx_hook_t hook);
wichat_rx_hook_t wichat_get_rx_hook(void);

// Pin channel — when set, detection.cpp stays on this channel instead of hopping.
// 0 = resume hopping.
void wichat_pin_channel(uint8_t ch);
uint8_t wichat_pinned_channel(void);

// Called to send a WiChat frame — briefly takes the radio
// Returns 0 on success.
int wichat_send_frame(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif
