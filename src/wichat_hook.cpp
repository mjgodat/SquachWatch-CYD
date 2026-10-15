// wichat_hook.cpp — WiChat background mesh service
#include "wichat_hook.h"
#include <esp_wifi.h>
#include <Arduino.h>

static wichat_rx_hook_t s_hook = nullptr;
static uint8_t s_pinnedCh = 0;

void wichat_set_rx_hook(wichat_rx_hook_t hook) { s_hook = hook; }
wichat_rx_hook_t wichat_get_rx_hook(void) { return s_hook; }

void wichat_pin_channel(uint8_t ch) { s_pinnedCh = ch; }
uint8_t wichat_pinned_channel(void) { return s_pinnedCh; }

int wichat_send_frame(const uint8_t* data, size_t len) {
    // Send raw 802.11 frame — this works alongside promiscuous RX
    esp_err_t r = esp_wifi_80211_tx(WIFI_IF_STA, data, (int)len, false);
    return (r == ESP_OK) ? 0 : -1;
}
