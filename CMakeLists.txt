# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wifi-attack-s3-repro)

# Deauth TX on IDF5/S3 requires overriding libnet80211.a's strong-global
# ieee80211_raw_frame_sanity_check(). The flag MUST reach the FINAL elf link;
# a component-only link flag may not propagate through static libs.
target_link_options(${PROJECT_NAME}.elf PRIVATE "-Wl,--allow-multiple-definition")
