# ESP32-S3 完整移植：Wi-Fi attacks using ESP32

本仓库是学术论文 **《Wi-Fi attacks using ESP32》（Richard Stehlík, FIT VUTBR, 2021）**
配套开源实现 `risinek/esp32-wifi-penetration-tool`（MIT）的 **ESP32-S3 完整功能移植**。

目标是功能 1:1：保留原项目全部组件、网页 UI、攻击类型/方法枚举、状态机、
HTTP 端点和抓包文件格式，只做让代码能在 ESP32-S3 + ESP-IDF 5.5.1 上
编译运行所需的最小适配。

## 与原项目完全一致的部分（未改源码逻辑）

- **网页后台**：`esp_http_server`，页面 `pages/page_index.h` 原样（gzip 页面），
  端点：`/`、`/ap-list`、`/run-attack`、`/status`、`/reset`、
  `/capture.hccapx`、`/capture.pcap`
- **攻击状态机**：`attack.c`（READY/RUNNING/FINISHED/TIMEOUT，超时定时器）
- **攻击类型**：`ATTACK_TYPE_PASSIVE`（原项目未实现）、`ATTACK_TYPE_HANDSHAKE`、
  `ATTACK_TYPE_PMKID`、`ATTACK_TYPE_DOS`
- **攻击方法**：`BROADCAST`（定时发 deauth）、`ROGUE_AP`（克隆 AP）、`PASSIVE`
- **抓包组件**：`frame_analyzer`、`pcap_serializer`、`hccapx_serializer`（原样）
- **deauth 发送**：`wsl_bypasser` 的符号覆盖机制（S3 上同样必需）

## IDF 4.1 → 5.5.1 / ESP32 → S3 的适配清单

| 原项目 | 本移植 | 原因 |
|---|---|---|
| `ESP_IF_WIFI_AP/STA` | `WIFI_IF_AP/STA` | IDF 5.x 移除旧枚举 |
| 无 NVS 初始化（`CONFIG_ESP32_WIFI_NVS_ENABLED=n`） | `app_main` 中 `nvs_flash_init()` | IDF 5.x WiFi 必需 |
| `wifi_controller/Kconfig` | `Kconfig.projbuild` | 组件配置须用此文件名 |
| `arpa/inet.h` 的 `ntohs/ntohl` | 自包含宏（`frame_analyzer_types.h`） | IDF 5.5 不再提供 |
| 组件 Kconfig 宏缺失默认值 | 全部保留在原 Kconfig.projbuild | 保证编译有定义 |
| `sniffer.c` filter 用 `else if` | 改为独立 `if` | 原逻辑有 bug（同时请求多类型会漏） |
| `wsl_bypasser` 用 `-Wl,-zmuldefs` | `-Wl,--allow-multiple-definition` | 现代 binutils 选项名 |
| `webserver` PRIV_REQUIRES `main`（循环依赖） | `webserver.c` 并入 main 组件编译 | IDF 5.x 禁止循环依赖 |
| 若干 `.c` 缺 `stdio.h`/`stdlib.h` | 补齐 | IDF 5.x 头文件更严格 |

以上均为编译/API 层面的最小改动，**没有任何功能删减或行为改写**。

## 编译（GitHub Actions 云端，无需本地装 ESP-IDF）

仓库自带 `.github/workflows/build.yml`，用乐鑫官方
`espressif/esp-idf-ci-action@v1`，target `esp32s3`，IDF `v5.5.1`。

推送到 main 即自动编译；成功后固件回写到仓库 `firmware/` 目录
（可直接下载，无需 Artifact 权限）：

- `bootloader.bin` → 0x0
- `partition-table.bin` → 0x8000
- `wifi-attack-s3-repro.bin` → 0x10000

`flash_args` 已生成，网页烧录台可自动读取。

## 使用（网页控制台，与原项目相同）

1. 烧录固件（本地网页烧录台 `../esp32-flasher`，http://127.0.0.1:8765）
2. 连接 WiFi `ManagementAP`（密码 `mgmtadmin`）
3. 浏览器打开 `http://192.168.4.1`
4. 原项目界面：Scan → 选目标 → 选攻击类型与方法 → 设超时 → Run → 轮询状态 → 下载

桌面交付包：`~/Desktop/ESP32-S3握手包工具/`（含固件、烧录脚本、网页入口、说明）。

## 合规边界

这是学术复现工具，仅用于你拥有或已明确授权的网络。论文作者亦强调此点。
开启 802.11w/PMF（WPA3 等）的路由器对 deauth 类方法有协议层防护，
这是论文建议的缓解措施之一。
