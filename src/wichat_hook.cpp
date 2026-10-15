// wichat_hook.cpp — WiChat background mesh service
#include "wichat_hook.h"
#include <esp_wifi.h>
#include <Arduino.h>

static wichat_rx_hook_t s_hook = nullptr;

void wichat_set_rx_hook(wichat_rx_hook_t hook) { s_hook = hook; }
wichat_rx_hook_t wichat_get_rx_hook(void) { return s_hook; }

int wichat_send_frame(const uint8_t* data, size_t len) {
    // Send raw 802.11 frame — this works alongside promiscuous RX
    esp_err_t r = esp_wifi_80211_tx(WIFI_IF_STA, data, (int)len, false);
    return (r == ESP_OK) ? 0 : -1;
}
