# ESP32-S3 复现：Wi-Fi attacks using ESP32（路径 B）

这是对学术论文 **《Wi-Fi attacks using ESP32》（Richard Stehlík, FIT VUTBR, 2021）**
核心贡献的移植复现，目标芯片为 **ESP32-S3**。

原项目：`risinek/esp32-wifi-penetration-tool`（该论文的配套开源实现，MIT）。

## 复现的是什么

论文 3.3 节 / 图 5 提出的 **rogue-AP deauthentication**（本文称"路径 B"）：

1. 扫描目标 AP，取得 SSID 与 BSSID；
2. 用 `esp_wifi_set_mac(WIFI_IF_AP, bssid)` 把 ESP32 的 AP 接口 MAC 改成目标 BSSID；
3. 用相同 SSID、相同信道、相同认证模式建一个克隆 AP；
4. 依据 802.11i，AP 对收到的未认证 station 帧会自动回 deauth 帧——
   **因此不需要帧注入，也不需要原项目里那个针对老 ESP32 闭源栈的 `wsl_bypasser`**。

`wsl_bypasser` 之所以没移植：它覆盖的 `ieee80211_raw_frame_sanity_check`
是 2021 年经典 ESP32（IDF 4.1）闭源 WiFi 栈的内部符号，ESP32-S3 的新栈中不存在，
`-zmuldefs` 无从覆盖。这也正是本复现选择路径 B 的技术原因。

## 与原文的适配差异（IDF 4.1 → 5.x，ESP32 → S3）

| 原项目 | 本复现 |
|---|---|
| `ESP_IF_WIFI_AP` | `WIFI_IF_AP`（IDF 5.x 已移除旧宏） |
| 无 `esp_netif` 初始化 | 补齐 `esp_netif_init()` + `esp_netif_create_default_wifi_ap/sta()` |
| 无显式事件循环 | 补齐 `esp_event_loop_create_default()` + 事件处理器 |
| `CONFIG_*` Kconfig 宏 | 改为头文件默认值 + `Kconfig.projbuild`（便于独立编译） |
| 预编译 bin（经典 ESP32） | 云端针对 `esp32s3` 重新编译 |

保留原样（纯逻辑、与芯片无关）：`frame_analyzer`、`pcap_serializer`、`hccapx_serializer`。

## 编译：GitHub Actions 云端（无需本地安装 ESP-IDF）

项目自带 `.github/workflows/build.yml`，使用乐鑫官方 `espressif/esp-idf-ci-action@v1`，
target 为 `esp32s3`，IDF 版本 `v5.5.1`。

步骤：
1. 在 GitHub 新建一个仓库（public 或 private 均可）；
2. 把本目录所有文件上传到该仓库（网页上传即可，无需命令行）；
3. 进入仓库 **Actions** 标签 → 左侧选 **Build ESP32-S3 firmware** → **Run workflow**；
4. 等待编译完成（约 3-8 分钟），在本次运行详情底部 **Artifacts** 处下载
   `esp32s3-repro-firmware`；
5. 解压得到 `bootloader.bin`、`partition-table.bin`、应用 bin、`flash_args`。

## 烧录：本地网页烧录台（无需安装 esptool 命令行）

工作区已有网页烧录控制台：`/Users/wangda/WorkBuddy/2026-11-26-14-24-58/esp32-flasher`

```bash
cd /Users/wangda/WorkBuddy/2026-11-26-14-24-58/esp32-flasher
.venv/bin/python server.py
# 浏览器打开 http://127.0.0.1:8765
```

板子串口：`/dev/cu.usbmodem5C381455561`（ESP32-S3 原生 USB，免驱）。
按网页提示上传固件各 bin 并填写地址（地址见 `flash_args`），点击烧录。

也可用一行命令（ firmware 目录内）：
```bash
esptool.py --port /dev/cu.usbmodem5C381455561 --baud 460800 write_flash @flash_args
```

## 运行与验证

烧录后打开串口（115200）：
```bash
screen /dev/cu.usbmodem5C381455561 115200
```
（退出：`Ctrl+A` 再 `Ctrl+D`）

启动后扫描并打印附近 AP 列表，然后出现菜单：

```
1) Capture handshake -> export .hccapx + .pcap
2) Path B: clone-AP deauth (paper sec.3.3)
```

### 模式 1：抓取握手包（拿到 .hccapx / .pcap）

1. 输入 `1`，回车；
2. 输入 **你自己路由器的精确 SSID**，回车；
3. 板子在该 AP 信道启动监听模式，提示你「断开并重连一台客户端」；
4. 拿手机/笔记本断开该 WiFi 再连上，触发 4-way handshake；
5. 抓到 M1/M2 后再多收 3 秒，串口会输出两段 base64 标记块：
   ```
   ===HCCAPX_BEGIN=== ... ===HCCAPX_END===
   ===PCAP_BEGIN===    ... ===PCAP_END===
   ```
6. 在工作区双击 **`接收握手包.command`**，脚本自动读串口、解码，并把
   `握手包_时间戳.hccapx` 和 `握手包_时间戳.pcap` 存到桌面。

   - `.hccapx` → 可直接给 hashcat 用；
   - `.pcap` → 可用 Wireshark 打开，过滤 `eapol` 查看握手过程。

抓包最长等待 120 秒；超时仍未抓到时，确认客户端确实重连了、且 SSID 拼写正确。

### 模式 2：路径 B 克隆 AP deauth

1. 输入 `2`，回车；
2. 输入 **你自己路由器的精确 SSID**，回车；
3. 克隆 AP 运行 30 秒（802.11i 原生 deauth 生效），随后自动恢复 MAC 与管理 AP；
4. 用 Wireshark 观察 deauth 帧，对照论文第 4.4 节实验结论。

**非交互模式**：在 `menuconfig` 打开 `REPRO_RUN_DEMO` 并填入 `REPRO_TARGET_SSID`
可跳过串口输入（仅用于自动化实验，目标仍须为你自己的 AP；此模式只影响菜单选项 2）。

## 合规边界（务必遵守）

- 本程序只对**你拥有或已获明确书面授权**的 AP 运行；作者论文亦强调此点。
- 程序刻意设计为手动输入目标 SSID，**没有**自动扫描-攻击循环，避免误伤他人网络。
- 本复现**不含**原项目的 DoS 洪水、Evil Twin 钓鱼、凭证窃取等攻击；
  仅实现论文核心学术贡献（路径 B）。
- 802.11w（管理帧保护）开启的 AP 对此方法有防护，正是论文建议的缓解措施之一。
