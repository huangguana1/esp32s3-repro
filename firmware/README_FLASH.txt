ESP32-S3 1:1 functional port of risinek/esp32-wifi-penetration-tool
Paper: "Wi-Fi attacks using ESP32", R. Stehlik, FIT VUTBR, 2021

FLASH (esptool v4.7+ installed in the local web flasher):
  esptool.py --port <PORT> --baud 460800 write_flash @flash_args
Run this from the firmware/ directory (flash_args lists offsets).

Or use the local web flasher at http://127.0.0.1:8765

USAGE (web UI - same as upstream project):
  1. Connect to WiFi "ManagementAP" (password: mgmtadmin)
  2. Open http://192.168.4.1 in a browser
  3. Scan APs, choose target, select attack type (HANDSHAKE / PMKID / DOS)
     and method (BROADCAST / ROGUE_AP / PASSIVE), set timeout, run.
  4. Poll /status; download /capture.hccapx and /capture.pcap.
All upstream endpoints are preserved: /, /ap-list, /run-attack,
/status, /reset, /capture.hccapx, /capture.pcap.
LEGAL: authorised / own networks only.
