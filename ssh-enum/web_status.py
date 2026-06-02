#!/usr/bin/env python3
"""
SSH User Enumeration (CVE-2018-15473) 웹 상태 UI
포트 9082 에서 SSH 서비스 상태 및 취약점 정보를 제공합니다.
Python 3.5 호환 (ubuntu:16.04)
"""
import http.server
import subprocess
import socket
import pwd

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH User Enum CVE-2018-15473</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #161b22, #21262d); padding: 24px 32px; border-bottom: 1px solid #30363d; }
  .header h1 { font-size: 1.6rem; color: #79c0ff; }
  .header .cve { font-size: 0.9rem; color: #8b949e; margin-top: 4px; }
  .container { max-width: 900px; margin: 0 auto; padding: 32px 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
  .card h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.05em; }
  .status-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot.green { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .dot.red { background: #f85149; box-shadow: 0 0 6px #f85149; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-size: 0.82rem; overflow-x: auto; color: #79c0ff; line-height: 1.6; }
  .cmd { background: #0d1117; border-left: 3px solid #79c0ff; padding: 10px 14px; border-radius: 0 6px 6px 0; font-family: monospace; font-size: 0.85rem; color: #e6edf3; margin: 6px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  td, th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 500; }
  .severity { color: #f0883e; font-weight: 600; }
  .user-badge { display: inline-block; padding: 1px 8px; background: #1c2e4a; color: #58a6ff; border-radius: 4px; font-family: monospace; font-size: 0.82rem; margin: 2px; }
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F510; SSH User Enumeration</h1>
  <div class="cve">CVE-2018-15473 &nbsp;|&nbsp; OpenSSH &lt; 7.7 사용자 열거 취약점</div>
</div>
<div class="container">

  <div class="card">
    <h2>서비스 상태</h2>
    <div class="status-row">
      <div class="dot SSH_DOT_PLACEHOLDER"></div>
      <span>SSH 서비스 (포트 22): <strong>SSH_STATUS_PLACEHOLDER</strong></span>
    </div>
    <div style="margin-top:8px;font-size:0.85rem;color:#8b949e">
      OpenSSH 버전: <strong style="color:#e6edf3">SSH_VERSION_PLACEHOLDER</strong>
    </div>
  </div>

  <div class="card">
    <h2>취약점 정보</h2>
    <table>
      <tr><th>항목</th><th>내용</th></tr>
      <tr><td>CVE</td><td>CVE-2018-15473</td></tr>
      <tr><td>CVSS Score</td><td class="severity">5.3 (Medium)</td></tr>
      <tr><td>영향 버전</td><td>OpenSSH 7.7 미만 전체</td></tr>
      <tr><td>공격 유형</td><td>사용자 이름 존재 여부 원격 열거 (User Enumeration)</td></tr>
      <tr><td>공격 조건</td><td>네트워크 접근 가능 + SSH 포트 오픈</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>공격 원리</h2>
    <pre>OpenSSH의 userauth_pubkey() 함수에서
존재하는 사용자와 존재하지 않는 사용자에 대해
서로 다른 응답 패킷을 반환하는 취약점.

- 존재하는 사용자    → SSH_MSG_USERAUTH_FAILURE (정상 응답)
- 존재하지 않는 사용자 → 연결 끊김 / 다른 에러 코드

이를 통해 공격자는 유효한 사용자 이름을 사전 대입으로 열거 가능.</pre>
  </div>

  <div class="card">
    <h2>컨테이너 내 테스트 계정</h2>
    <p style="font-size:0.83rem;color:#8b949e;margin-bottom:12px">아래 계정들이 이 컨테이너에 존재합니다 (열거 테스트용):</p>
    USER_BADGES_PLACEHOLDER
  </div>

  <div class="card">
    <h2>분석 명령어 (호스트에서 실행)</h2>
    <p style="font-size:0.83rem;color:#8b949e;margin-bottom:12px">아래 명령어는 호스트 터미널에서 실행하세요.</p>
    <div class="cmd">ssh -p 2222 testuser@localhost</div>
    <div class="cmd">nmap -p 2222 --script ssh-auth-methods localhost</div>
    <div class="cmd">ssh-keyscan -p 2222 localhost</div>
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

def get_ssh_version():
    try:
        result = subprocess.Popen(
            ['ssh', '-V'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = result.communicate()
        return (err or out).decode('utf-8').strip()
    except Exception:
        return "알 수 없음"

def get_test_users():
    target = ['testuser', 'admin', 'developer']
    badges = ""
    for u in target:
        try:
            pwd.getpwnam(u)
            badges += '<span class="user-badge">' + u + '</span>\n'
        except Exception:
            pass
    if not badges:
        badges = "<span style='color:#8b949e'>계정 정보를 불러올 수 없습니다.</span>"
    return badges

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        ssh_up = check_port(22)
        html = HTML_TEMPLATE
        html = html.replace('SSH_DOT_PLACEHOLDER', 'green' if ssh_up else 'red')
        html = html.replace('SSH_STATUS_PLACEHOLDER', '실행 중 &#x2713;' if ssh_up else '중지됨 &#x2717;')
        html = html.replace('SSH_VERSION_PLACEHOLDER', get_ssh_version())
        html = html.replace('USER_BADGES_PLACEHOLDER', get_test_users())
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 9082), Handler)
    print("SSH Enum web UI: http://0.0.0.0:9082")
    server.serve_forever()
