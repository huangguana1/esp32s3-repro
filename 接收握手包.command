#!/bin/bash
# Double-click this file to receive the handshake export from ESP32-S3.
cd "$(dirname "$0")" || exit 1

PY="/Users/wangda/WorkBuddy/2026-11-26-14-24-58/esp32-flasher/.venv/bin/python"
if [ ! -x "$PY" ]; then
    PY="$(command -v python3)"
fi

exec "$PY" "接收握手包.py"
