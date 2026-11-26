ESP32-S3 reproduction firmware - Path B rogue-AP deauth
Paper: "Wi-Fi attacks using ESP32", R. Stehlik, FIT VUTBR, 2021

FLASH (esptool v4.7+ installed in the local web flasher):
  esptool.py --port <PORT> --baud 460800 write_flash @flash_args
Run this from the firmware/ directory (flash_args lists offsets).

Or use the local web flasher at http://127.0.0.1:8765

USAGE (serial console, 115200 baud):
  - Board scans nearby APs and prints a menu.
  - [1] Capture handshake: type the EXACT SSID of YOUR OWN router,
        disconnect/reconnect a client, then run the macOS helper
        "接收握手包.command" to decode .hccapx + .pcap to Desktop.
  - [2] Path B clone-AP deauth runs for 30 s, then restores state.
LEGAL: authorised / own networks only.
