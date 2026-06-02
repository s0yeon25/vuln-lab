#!/bin/bash
set -e

# Samba 로그 디렉터리 생성
mkdir -p /var/log/samba /run/samba

# smbd 백그라운드 시작
smbd --foreground --no-process-group &
SMB_PID=$!

echo "[*] smbd started (PID $SMB_PID)"
echo "[*] Starting web UI on port 8081..."

# 웹 UI 포그라운드 실행
python3 /web_status.py
