#!/bin/bash
set -e

# SSH host keys 생성
ssh-keygen -A

# sshd 백그라운드 시작
/usr/sbin/sshd -D &
SSH_PID=$!

echo "[*] sshd started (PID $SSH_PID)"
echo "[*] Starting web UI on port 8082..."

# 웹 UI 포그라운드 실행
python3 /web_status.py
