#!/usr/bin/env python3
"""
SambaCry (CVE-2017-7494) 웹 상태 UI
포트 8081 에서 SMB 서비스 상태 및 취약점 정보를 제공합니다.
"""
import http.server
import subprocess
import socket
import json
import os

HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SambaCry CVE-2017-7494</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #161b22, #21262d); padding: 24px 32px; border-bottom: 1px solid #30363d; }
  .header h1 { font-size: 1.6rem; color: #f0883e; }
  .header .cve { font-size: 0.9rem; color: #8b949e; margin-top: 4px; }
  .container { max-width: 900px; margin: 0 auto; padding: 32px 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
  .card h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.05em; }
  .status-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot.green { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .dot.red { background: #f85149; box-shadow: 0 0 6px #f85149; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.78rem; font-weight: 600; }
  .badge.critical { background: #6e2b2b; color: #f85149; border: 1px solid #f85149; }
  .badge.info { background: #1c2e4a; color: #58a6ff; border: 1px solid #388bfd; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-size: 0.82rem; overflow-x: auto; color: #79c0ff; line-height: 1.6; }
  .cmd { background: #0d1117; border-left: 3px solid #f0883e; padding: 10px 14px; border-radius: 0 6px 6px 0; font-family: monospace; font-size: 0.85rem; color: #e6edf3; margin: 6px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  td, th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 500; }
  .severity { color: #f85149; font-weight: 600; }
</style>
</head>
<body>
<div class="header">
  <h1>🪱 SambaCry</h1>
  <div class="cve">CVE-2017-7494 &nbsp;|&nbsp; Samba 3.5.0 ~ 4.6.3 원격 코드 실행 취약점</div>
</div>
<div class="container">

  <div class="card">
    <h2>서비스 상태</h2>
    <div class="status-row">
      <div class="dot {smb_dot}"></div>
      <span>SMB 서비스 (포트 445): <strong>{smb_status}</strong></span>
    </div>
    <div class="status-row">
      <div class="dot {nb_dot}"></div>
      <span>NetBIOS (포트 139): <strong>{nb_status}</strong></span>
    </div>
  </div>

  <div class="card">
    <h2>취약점 정보</h2>
    <table>
      <tr><th>항목</th><th>내용</th></tr>
      <tr><td>CVE</td><td>CVE-2017-7494</td></tr>
      <tr><td>CVSS Score</td><td class="severity">9.8 (Critical)</td></tr>
      <tr><td>영향 버전</td><td>Samba 3.5.0 ~ 4.6.3</td></tr>
      <tr><td>공격 유형</td><td>원격 코드 실행 (RCE) — 공유 디렉터리에 .so 파일 업로드 후 로드</td></tr>
      <tr><td>필요 조건</td><td>쓰기 가능한 공유 폴더 접근 권한</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>공격 원리</h2>
    <pre>1. 공격자가 쓰기 가능한 SMB 공유에 악성 .so (shared library) 업로드
2. IPC$ 파이프를 통해 samba에게 해당 파일 경로를 로드하도록 요청
3. smbd가 root 권한으로 .so 파일 실행 → 원격 코드 실행</pre>
  </div>

  <div class="card">
    <h2>분석 명령어 (호스트에서 실행)</h2>
    <p style="font-size:0.83rem;color:#8b949e;margin-bottom:12px">아래 명령어는 호스트 터미널에서 실행하세요.</p>
    <div class="cmd">smbclient -L //localhost -p 1445 -N</div>
    <div class="cmd">smbclient //localhost/share -p 1445 -N</div>
    <div class="cmd">nmap -p 1445 --script smb-vuln-cve-2017-7494 localhost</div>
    <div class="cmd">python3 -m smb.exploit --target localhost --port 1445 --share share</div>
  </div>

  <div class="card">
    <h2>Samba 버전 정보</h2>
    <pre>{samba_version}</pre>
  </div>

</div>
</body>
</html>
"""

def check_port(port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

def get_samba_version():
    try:
        result = subprocess.run(['smbd', '--version'], capture_output=True, text=True)
        return result.stdout.strip() or result.stderr.strip()
    except:
        return "버전 정보를 가져올 수 없습니다."

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        smb_up = check_port(445)
        nb_up = check_port(139)
        html = HTML.format(
            smb_dot='green' if smb_up else 'red',
            smb_status='실행 중 ✓' if smb_up else '중지됨 ✗',
            nb_dot='green' if nb_up else 'red',
            nb_status='실행 중 ✓' if nb_up else '중지됨 ✗',
            samba_version=get_samba_version(),
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 8081), Handler)
    print("SambaCry web UI: http://0.0.0.0:8081")
    server.serve_forever()
