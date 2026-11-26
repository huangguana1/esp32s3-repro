idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES wifi_controller frame_analyzer pcap_serializer hccapx_serializer esp_wifi esp_event esp_netif driver nvs_flash esp_timer mbedtls)
