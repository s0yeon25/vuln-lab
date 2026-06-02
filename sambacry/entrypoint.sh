#!/bin/bash
set -e

mkdir -p /var/log/samba /run/samba

# 웹 UI를 먼저 백그라운드로 시작 (포트 8081 선점)
python3 /web_status.py &
WEB_PID=$!
echo "[*] Web UI started (PID $WEB_PID) on port 8081"

# 잠깐 대기 후 smbd 시작
sleep 1

# smbd 포그라운드 실행
echo "[*] Starting smbd..."
exec smbd --foreground --no-process-group
