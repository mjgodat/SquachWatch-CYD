/* radio_esp32.cpp — WiChat radio shim for SquatchWatch
 * Uses SquatchWatch's shared WiFi radio instead of taking it over.
 * TX: esp_wifi_80211_tx directly (brief, non-blocking)
 * RX: handled by wichat_hook in SquatchWatch's promiscuous callback */
#include "radio_esp32.h"
#include "wichat_config.h"
#include <Arduino.h>
#include <string.h>
#include <esp_wifi.h>

static uint8_t s_local_mac[6] = {0};
static int s_tx_count = 0;

int radio_esp32_init(uint8_t channel) {
    // Don't init WiFi — SquatchWatch owns it.
    // Just get our MAC and set channel.
    esp_wifi_get_mac(WIFI_IF_STA, s_local_mac);
    // Don't force channel — SquatchWatch hops channels for scanning.
    // WiChat frames will be received when scanner visits channel 1.
    Serial.printf("[RADIO-SHIM] MAC: %02X:%02X:%02X:%02X:%02X:%02X (shared radio)\n",
        s_local_mac[0], s_local_mac[1], s_local_mac[2],
        s_local_mac[3], s_local_mac[4], s_local_mac[5]);
    return 0;
}

void radio_esp32_get_mac(uint8_t mac[6]) {
    memcpy(mac, s_local_mac, 6);
}

int radio_esp32_tx(const uint8_t *data, size_t len) {
    // Brief TX — send raw 802.11 frame without stopping scanner
    esp_err_t r = esp_wifi_80211_tx(WIFI_IF_STA, data, (int)len, false);
    if (r == ESP_OK) s_tx_count++;
    return (r == ESP_OK) ? 0 : -1;
}

int radio_esp32_rx(uint8_t *buf, size_t max_len, int8_t *rssi) {
    // RX is handled by the wichat_hook in detection.cpp's callback.
    // This function is a no-op — the toolbox drains the queue directly.
    (void)buf; (void)max_len; (void)rssi;
    return 0;
}

void radio_esp32_print_stats(void) {
    Serial.printf("[RADIO-SHIM] TX: %d frames (shared radio)\n", s_tx_count);
}
