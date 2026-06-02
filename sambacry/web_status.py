#!/usr/bin/env python3
"""
SambaCry (CVE-2017-7494) 웹 상태 UI - Python 3.5+ 호환
"""
import http.server
import subprocess
import socket

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
  .dot-green { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .dot-red { background: #f85149; box-shadow: 0 0 6px #f85149; }
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
  <h1>&#x1F4A3; SambaCry</h1>
  <div class="cve">CVE-2017-7494 &nbsp;|&nbsp; Samba 3.5.0 ~ 4.6.3 원격 코드 실행 취약점</div>
</div>
<div class="container">
  <div class="card">
    <h2>서비스 상태</h2>
    <div class="status-row">
      <div class="dot SMB_DOT_CLASS"></div>
      <span>SMB 서비스 (포트 445): <strong>SMB_STATUS</strong></span>
    </div>
    <div class="status-row">
      <div class="dot NB_DOT_CLASS"></div>
      <span>NetBIOS (포트 139): <strong>NB_STATUS</strong></span>
    </div>
  </div>
  <div class="card">
    <h2>취약점 정보</h2>
    <table>
      <tr><th>항목</th><th>내용</th></tr>
      <tr><td>CVE</td><td>CVE-2017-7494</td></tr>
      <tr><td>CVSS Score</td><td class="severity">9.8 (Critical)</td></tr>
      <tr><td>영향 버전</td><td>Samba 3.5.0 ~ 4.6.3</td></tr>
      <tr><td>공격 유형</td><td>원격 코드 실행 (RCE)</td></tr>
      <tr><td>필요 조건</td><td>쓰기 가능한 공유 폴더 접근 권한</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>공격 원리</h2>
    <pre>1. 공격자가 쓰기 가능한 SMB 공유에 악성 .so 파일 업로드
2. IPC$ 파이프를 통해 smbd에게 해당 파일 경로 로드 요청
3. smbd가 root 권한으로 .so 파일 실행 - 원격 코드 실행</pre>
  </div>
  <div class="card">
    <h2>분석 명령어 (호스트에서 실행)</h2>
    <div class="cmd">smbclient -L //localhost -p 1445 -N</div>
    <div class="cmd">smbclient //localhost/share -p 1445 -N</div>
    <div class="cmd">nmap -p 1445 --script smb-vuln-cve-2017-7494 localhost</div>
  </div>
  <div class="card">
    <h2>Samba 버전</h2>
    <pre>SAMBA_VERSION</pre>
  </div>
</div>
</body>
</html>"""

def check_port(port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except Exception:
        return False

def get_samba_version():
    try:
        result = subprocess.Popen(
            ['smbd', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = result.communicate()
        return (out or err).decode('utf-8').strip()
    except Exception:
        return "버전 정보를 가져올 수 없습니다."

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        smb_up = check_port(445)
        nb_up = check_port(139)
        html = HTML
        html = html.replace('SMB_DOT_CLASS', 'dot-green' if smb_up else 'dot-red')
        html = html.replace('SMB_STATUS', '&#x2713; 실행 중' if smb_up else '&#x2717; 중지됨')
        html = html.replace('NB_DOT_CLASS', 'dot-green' if nb_up else 'dot-red')
        html = html.replace('NB_STATUS', '&#x2713; 실행 중' if nb_up else '&#x2717; 중지됨')
        html = html.replace('SAMBA_VERSION', get_samba_version())
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 9081), Handler)
    print("SambaCry web UI: http://0.0.0.0:9081")
    server.serve_forever()
