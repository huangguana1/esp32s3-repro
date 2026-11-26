/**
 * @file wifi_controller.h
 * @brief ESP-IDF 5.x adapted WiFi controller (from risinek/esp32-wifi-penetration-tool)
 * Ported for ESP32-S3 reproduction of "Wi-Fi attacks using ESP32" (Stehlík, 2021)
 */
#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

#include <stdint.h>
#include <unistd.h>

#include "ap_scanner.h"
#include "sniffer.h"
#include "esp_wifi_types.h"

/* IDF 5.5 no longer exposes MACSTR/MAC2STR through the WiFi headers.
 * Provide a compatible fallback so logging keeps working. */
#ifndef MACSTR
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

/* Management AP credentials - made configurable instead of Kconfig */
#ifndef CONFIG_MGMT_AP_SSID
#define CONFIG_MGMT_AP_SSID "ManagementAP"
#endif
#ifndef CONFIG_MGMT_AP_PASSWORD
#define CONFIG_MGMT_AP_PASSWORD "mgmtadmin"
#endif
#ifndef CONFIG_MGMT_AP_MAX_CONNECTIONS
#define CONFIG_MGMT_AP_MAX_CONNECTIONS 4
#endif

void wifictl_ap_start(wifi_config_t *wifi_config);
void wifictl_ap_stop(void);
void wifictl_mgmt_ap_start(void);
void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]);
void wifictl_sta_disconnect(void);
void wifictl_set_ap_mac(const uint8_t *mac_ap);
void wifictl_get_ap_mac(uint8_t *mac_ap);
void wifictl_restore_ap_mac(void);
void wifictl_get_sta_mac(uint8_t *mac_sta);
void wifictl_set_channel(uint8_t channel);

#endif
