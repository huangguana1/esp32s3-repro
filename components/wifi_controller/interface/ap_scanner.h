/**
 * @file ap_scanner.h
 * @brief AP scanning interface (ESP-IDF 5.x adapted)
 */
#ifndef AP_SCANNER_H
#define AP_SCANNER_H

#include "esp_wifi_types.h"

/* Replacement for the original CONFIG_SCAN_MAX_AP Kconfig option */
#ifndef CONFIG_SCAN_MAX_AP
#define CONFIG_SCAN_MAX_AP 32
#endif

typedef struct {
    uint16_t count;
    wifi_ap_record_t records[CONFIG_SCAN_MAX_AP];
} wifictl_ap_records_t;

void wifictl_scan_nearby_aps(void);
const wifictl_ap_records_t *wifictl_get_ap_records(void);
const wifi_ap_record_t *wifictl_get_ap_record(unsigned index);

#endif
