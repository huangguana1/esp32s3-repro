/**
 * @file wifi_controller.c
 * @brief WiFi controller - ESP-IDF 5.x / ESP32-S3 adapted
 *
 * Original: risinek/esp32-wifi-penetration-tool (c) 2021 risinek, MIT
 * Adapted for the reproduction of the paper "Wi-Fi attacks using ESP32":
 *   - ESP_IF_WIFI_AP -> WIFI_IF_AP (removed in IDF 5.x)
 *   - Added esp_netif_init() + esp_netif_create_default_wifi_ap/sta() (mandatory since IDF 4.1+/5.x)
 *   - Added explicit event loop creation with netif event handlers
 *   - NVS flash init (disabled in original via CONFIG_ESP32_WIFI_NVS_ENABLED=n)
 *
 * Key primitive for the paper's contribution (rogue-AP deauth):
 *   esp_wifi_set_mac(WIFI_IF_AP, bssid) -- clone the target AP's MAC so the
 *   802.11i stack emits deauth frames natively, WITHOUT frame injection.
 */
#include "wifi_controller.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

static const char *TAG = "wifi_controller";

static bool wifi_init = false;
static uint8_t original_mac_ap[6];

/* Event handler for WiFi / IP events */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGD(TAG, "station " MACSTR " joined, AID=%d", MAC2STR(e->mac), e->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGD(TAG, "station " MACSTR " left, AID=%d", MAC2STR(e->mac), e->aid);
    }
}

/* Initialise WiFi in AP+STA mode (required for clone-AP + scanning at once) */
static void wifi_init_apsta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Remember the factory AP MAC so it can be restored after an attack */
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));
    ESP_LOGI(TAG, "Original AP MAC: " MACSTR, MAC2STR(original_mac_ap));

    wifi_init = true;
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    if (!wifi_init) {
        wifi_init_apsta();
    }
    /* IDF 5.x interface id (was ESP_IF_WIFI_AP in IDF 4.1) */
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop(void) {
    wifi_config_t wifi_config = {
        .ap = { .max_connection = 0 },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_LOGD(TAG, "AP stopped");
}

void wifictl_mgmt_ap_start(void) {
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]) {
    if (!wifi_init) {
        wifi_init_apsta();
    }
    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false,
        },
    };
    strncpy((char *)sta_wifi_config.sta.ssid, (const char *)ap_record->ssid, 32);
    if (password && password[0]) {
        strncpy((char *)sta_wifi_config.sta.password, password, 64);
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
}

void wifictl_sta_disconnect(void) {
    esp_wifi_disconnect();
}

/* ---- Core primitive of the paper's Path B: MAC cloning ---- */
void wifictl_set_ap_mac(const uint8_t *mac_ap) {
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, (uint8_t *)mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap) {
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(void) {
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta) {
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_set_channel(uint8_t channel) {
    if ((channel == 0) || (channel > 13)) {
        ESP_LOGE(TAG, "Channel out of range. Expected <1,13> but got %u", channel);
        return;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}
