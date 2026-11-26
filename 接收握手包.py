#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
接收 ESP32-S3 复现固件导出的握手包，解码后保存到桌面。

双击「接收握手包.command」运行即可。脚本会接管串口（等同于 screen），
你在窗口里输入 1 和自己的 SSID，触发客户端重连后，导出的 base64 会被
自动解码成 .hccapx 和 .pcap 存到桌面。
"""
import base64
import glob
import os
import re
import select
import sys
import threading
import time

import serial

TIMEOUT_SEC = 300
PORT_PATTERNS = [
    "/dev/cu.usbmodem*",
    "/dev/cu.wchusbserial*",
    "/dev/cu.usbserial*",
]


def pick_port():
    ports = []
    for pattern in PORT_PATTERNS:
        ports.extend(glob.glob(pattern))
    ports = sorted(set(ports))
    if not ports:
        print("[!] 没有找到串口设备。请先插上 ESP32-S3 板子。")
        sys.exit(1)
    if len(ports) == 1:
        print(f"[+] 使用串口: {ports[0]}")
        return ports[0]
    print("[?] 找到多个串口，请选择:")
    for i, port in enumerate(ports):
        print(f"    [{i}] {port}")
    while True:
        answer = input("输入序号: ").strip()
        if answer.isdigit() and 0 <= int(answer) < len(ports):
            return ports[int(answer)]
        print("   无效序号，请重试。")


def main():
    port = pick_port()
    try:
        ser = serial.Serial(port, 115200, timeout=0.2)
    except Exception as exc:
        print(f"[!] 打开串口失败: {exc}")
        sys.exit(1)

    state = None
    buffers = {}
    done = False
    start = time.time()

    def finish_if_ready():
        nonlocal done
        if "HCCAPX" in buffers and "PCAP" in buffers:
            done = True

    def process_line(raw):
        nonlocal state
        text = raw.strip()
        if not text:
            return

        if text.startswith("===HCCAPX_BEGIN==="):
            state = "HCCAPX"
            buffers["HCCAPX"] = []
            print("[*] 正在接收 HCCAPX ...")
            return
        if text.startswith("===PCAP_BEGIN==="):
            state = "PCAP"
            buffers["PCAP"] = []
            print("[*] 正在接收 PCAP ...")
            return
        if text.startswith("===HCCAPX_END===") and state == "HCCAPX":
            buffers["HCCAPX"] = "".join(buffers["HCCAPX"])
            state = None
            print("[+] HCCAPX 接收完成")
            finish_if_ready()
            return
        if text.startswith("===PCAP_END===") and state == "PCAP":
            buffers["PCAP"] = "".join(buffers["PCAP"])
            state = None
            print("[+] PCAP 接收完成")
            finish_if_ready()
            return

        if state and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
            buffers[state].append(text)
            return

        # ordinary console output - show short lines so the user sees progress
        if "repro" in text or "HANDSHAKE" in text or len(text) < 160:
            print(text)

    def reader():
        line = bytearray()
        while not done and (time.time() - start) < TIMEOUT_SEC:
            try:
                data = ser.read(1)
            except Exception:
                break
            if not data:
                continue
            if data in (b"\r", b"\n"):
                if line:
                    process_line(line.decode("utf-8", "ignore"))
                    line.clear()
            else:
                line += data

    threading.Thread(target=reader, daemon=True).start()

    print("=" * 64)
    print(" ESP32-S3 握手包接收器")
    print(" 在这个窗口里直接输入命令（等同于串口控制台）：")
    print("   1                选择和自己路由器握手包抓取")
    print("   你的WiFi名称      输入自己路由器的精确 SSID")
    print(" 然后让手机/笔记本断开该 WiFi 再连上，触发握手。")
    print(" 导出的文件会自动保存到桌面。")
    print("=" * 64)

    while not done and (time.time() - start) < TIMEOUT_SEC:
        readable, _, _ = select.select([sys.stdin], [], [], 0.3)
        if readable:
            text = sys.stdin.readline()
            if not text:
                break
            text = text.rstrip("\r\n")
            if text:
                ser.write((text + "\n").encode("utf-8"))

    ser.close()

    if not buffers:
        print("[!] 未收到握手包数据。请确认固件是新版、菜单选了 1、客户端已重连。")
        sys.exit(1)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    desktop = os.path.expanduser("~/Desktop")
    saved = []
    for key, ext in (("HCCAPX", "hccapx"), ("PCAP", "pcap")):
        encoded = buffers.get(key)
        if not encoded:
            continue
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            print(f"[!] {key} base64 解码失败: {exc}")
            continue
        if len(data) < 16:
            print(f"[!] {key} 数据过短，跳过")
            continue
        path = os.path.join(desktop, f"握手包_{timestamp}.{ext}")
        with open(path, "wb") as handle:
            handle.write(data)
        saved.append(path)
        print(f"[+] 已保存: {path}  ({len(data)} bytes)")

    if saved:
        print("")
        print("完成。.hccapx 可交给 hashcat；.pcap 可用 Wireshark 过滤 eapol 查看。")
    else:
        print("[!] 没有生成有效文件。")
        sys.exit(1)


if __name__ == "__main__":
    main()
