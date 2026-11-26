# webserver.c is compiled into the main component to break the main<->webserver
# circular dependency that IDF 5.x rejects (upstream IDF 4.1 tolerated it).
# All source files and logic remain identical to the upstream project.
idf_component_register(
    SRCS "attack_dos.c" "attack_method.c" "main.c" "attack_handshake.c"
         "attack_pmkid.c" "attack.c"
         "../components/webserver/webserver.c"
    INCLUDE_DIRS "." "../components/webserver/interface" "../components/webserver"
    REQUIRES wifi_controller frame_analyzer hccapx_serializer pcap_serializer wsl_bypasser
             esp_wifi esp_event esp_netif nvs_flash esp_timer esp_http_server log)
