idf_component_register(
    SRCS "wsl_bypasser.c"
    INCLUDE_DIRS "interface"
    REQUIRES esp_wifi
)
# IDF 5.x: allow our ieee80211_raw_frame_sanity_check() override to win over
# the strong-global symbol in libnet80211.a (same technique as upstream IDF 4.1).
target_link_libraries(${COMPONENT_LIB} "-Wl,--allow-multiple-definition")
