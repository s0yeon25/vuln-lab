import subprocess
import re
import platform
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────
# CVE 조치 방법 데이터
# ─────────────────────────────────────────

CVE_REMEDIATION = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "Critical (CVSS 10.0)",
        "description": "Apache Log4j2의 JNDI Lookup 기능을 악용한 원격 코드 실행 취약점",
        "impact": "공격자가 서버에서 임의 코드를 원격 실행 가능",
        "remediation": [
            "[즉시] Log4j 버전을 2.17.1 이상으로 업그레이드",
            "[즉시] JVM 옵션에 -Dlog4j2.formatMsgNoLookups=true 추가",
            "[즉시] 환경변수 LOG4J_FORMAT_MSG_NO_LOOKUPS=true 설정",
            "[방화벽] 서버의 아웃바운드 LDAP(389), RMI(1099) 포트 차단",
            "[모니터링] 로그에서 ${jndi: 패턴 탐지 규칙 추가",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ]
    },
    "CVE-2017-7494": {
        "name": "SambaCry",
        "severity": "Critical (CVSS 9.8)",
        "description": "Samba의 is_known_pipename() 함수에서 발생하는 원격 코드 실행 취약점",
        "impact": "쓰기 권한이 있는 SMB 공유를 통해 악성 라이브러리 업로드 후 root 권한으로 실행 가능",
        "remediation": [
            "[즉시] Samba 버전을 4.6.4 / 4.5.10 / 4.4.14 이상으로 업그레이드",
            "[설정] smb.conf에 'nt pipe support = no' 추가 후 재시작",
            "[네트워크] SMB 포트(445, 139)를 방화벽에서 외부 차단",
            "[권한] 공개 SMB 공유에 쓰기 권한 제거",
            "[모니터링] SMB 공유에 .so 파일 업로드 시 알림 설정",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7494",
            "https://www.samba.org/samba/security/CVE-2017-7494.html",
        ]
    },
    "CVE-2018-15473": {
        "name": "SSH User Enumeration",
        "severity": "Medium (CVSS 5.3)",
        "description": "OpenSSH에서 존재하지 않는 사용자와 존재하는 사용자에 대한 응답 차이로 계정 존재 여부를 확인 가능",
        "impact": "공격자가 유효한 시스템 계정 목록을 수집하여 브루트포스 공격에 활용 가능",
        "remediation": [
            "[즉시] OpenSSH 버전을 7.8 이상으로 업그레이드",
            "[설정] sshd_config에 'MaxAuthTries 3' 설정으로 시도 횟수 제한",
            "[설정] 불필요한 계정 비활성화 및 root 직접 로그인 금지 (PermitRootLogin no)",
            "[설정] 패스워드 인증 비활성화 후 키 기반 인증만 허용 (PasswordAuthentication no)",
            "[네트워크] SSH 포트를 기본 22에서 변경 또는 특정 IP만 허용",
            "[모니터링] Fail2Ban 등 도구로 반복 접속 시도 자동 차단",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
            "https://www.openssh.com/releasenotes.html",
        ]
    },
}


# ─────────────────────────────────────────
# 1. OS 추정 (TTL 기반)
# ─────────────────────────────────────────

def get_ttl(target_ip):
    """TTL 값으로 OS 추정"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", target_ip],
                capture_output=True, text=True, timeout=5
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", target_ip],
                capture_output=True, text=True, timeout=5
            )

        ttl_match = re.search(r'[Tt][Tt][Ll][=<](\d+)', result.stdout)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            print(f"[*] TTL 값: {ttl}")

            if ttl <= 64:
                return ttl, "Linux / Unix 계열"
            elif ttl <= 128:
                return ttl, "Windows 계열"
            else:
                return ttl, "알 수 없음 (네트워크 홉 가능성)"
        else:
            return None, "TTL 추출 실패"

    except subprocess.TimeoutExpired:
        return None, "핑 타임아웃 - 호스트 응답 없음"
    except Exception as e:
        return None, f"오류: {e}"


# ─────────────────────────────────────────
# 2. Nuclei CVE 탐지
# ─────────────────────────────────────────

def run_nuclei_scan(targets: list) -> list:
    """Nuclei로 CVE 탐지 실행"""
    results = []

    print(f"\n[*] Nuclei CVE 스캔 시작 - 대상 {len(targets)}개")
    print("-" * 50)

    for target in targets:
        print(f"\n[*] 스캔 중: {target}")

        try:
            cmd = [
                "nuclei",
                "-u", target,
                "-t", TARGET_TEMPLATES[target],
                "-severity", "critical,high,medium",
                "-silent",
                "-no-color",
                "-timeout", "10"
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            detected = parse_nuclei_output(proc.stdout, target)
            results.extend(detected)

            if not detected:
                print(f"   [-] 탐지된 CVE 없음")

        except FileNotFoundError:
            print("[!] Nuclei가 설치되어 있지 않습니다.")
            print("    설치: https://github.com/projectdiscovery/nuclei")
            break
        except subprocess.TimeoutExpired:
            print(f"   [!] {target} 스캔 타임아웃")

    return results


def parse_nuclei_output(output: str, target: str) -> list:
    """Nuclei 출력에서 CVE 정보 추출"""
    detected = []

    # Nuclei 출력 형식 예시:
    # [CVE-2021-44228] [http] [critical] http://localhost:9080
    pattern = re.compile(
        r'\[(CVE-\d{4}-\d+)\]\s+\[(\w+)\]\s+\[(\w+)\]\s+(.+)'
    )

    for line in output.strip().split('\n'):
        if not line:
            continue

        match = pattern.search(line)
        if match:
            cve_id   = match.group(1)
            protocol = match.group(2)
            severity = match.group(3)
            url      = match.group(4)

            detected.append({
                "cve": cve_id,
                "protocol": protocol,
                "severity": severity,
                "target": url
            })

            severity_label = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]"}.get(severity, "[INFO]")
            print(f"   {severity_label} {cve_id} - {url}")

    return detected


# ─────────────────────────────────────────
# 3. 결과 요약 출력
# ─────────────────────────────────────────

def print_summary(ttl, os_guess: str, nuclei_results: list):
    """최종 결과 요약 출력"""
    print("\n" + "=" * 60)
    print("               스캔 결과 요약")
    print("=" * 60)

    print(f"\n[ OS 추정 ]")
    if ttl:
        print(f"  TTL {ttl} -> {os_guess}")
    else:
        print(f"  {os_guess}")

    print(f"\n[ 탐지된 CVE ] - 총 {len(nuclei_results)}건")

    if nuclei_results:
        by_severity = {}
        for r in nuclei_results:
            s = r["severity"]
            by_severity.setdefault(s, []).append(r["cve"])

        for severity, cves in by_severity.items():
            label = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]"}.get(severity, "[INFO]")
            print(f"\n  {label}")
            for cve in cves:
                print(f"     - {cve}")
    else:
        print("  탐지된 CVE 없음")

    print("\n" + "=" * 60)


# ─────────────────────────────────────────
# 4. 관리자 조치 보고서 출력
# ─────────────────────────────────────────

def print_remediation_report(nuclei_results: list):
    """탐지된 CVE에 대한 관리자용 조치 보고서 출력"""

    print("\n" + "=" * 60)
    print("         관리자 조치 보고서")
    print("=" * 60)

    if not nuclei_results:
        print("\n탐지된 취약점이 없습니다.")
        return

    detected_cves = list({r["cve"] for r in nuclei_results})

    print(f"\n총 {len(detected_cves)}개의 취약점이 탐지되었습니다.\n")

    for cve_id in detected_cves:
        info = CVE_REMEDIATION.get(cve_id)

        if not info:
            print(f"[{cve_id}] 조치 정보 없음")
            print(f"  NVD 참고: https://nvd.nist.gov/vuln/detail/{cve_id}\n")
            continue

        print(f"{'─' * 60}")
        print(f"[{cve_id}] {info['name']}")
        print(f"  심각도  : {info['severity']}")
        print(f"  설명    : {info['description']}")
        print(f"  영향    : {info['impact']}")
        print(f"\n  조치 방법:")
        for step in info["remediation"]:
            print(f"    - {step}")
        print(f"\n  참고 자료:")
        for ref in info["references"]:
            print(f"    - {ref}")
        print()

    print("=" * 60)
    print("  [즉시] 항목부터 우선 조치하시기 바랍니다.")
    print("=" * 60)


def send_email_report(nuclei_results: list, receiver_email: str):
    """탐지된 CVE 조치 보고서를 이메일로 전송"""

    # ── 여기에 본인 정보 입력 ──
    SENDER_EMAIL = "이메일아이디@gmail.com"
    APP_PASSWORD  = "16자리비밀번호"
    # ───────────────────────────

    if not nuclei_results:
        print("\n[*] 탐지된 CVE 없음 - 이메일 전송 생략")
        return

    detected_cves = list({r["cve"] for r in nuclei_results})

    # 이메일 본문 작성
    body = "=" * 50 + "\n"
    body += "       취약점 탐지 보고서 (자동 발송)\n"
    body += "=" * 50 + "\n\n"
    body += f"총 {len(detected_cves)}개의 취약점이 탐지되었습니다.\n\n"

    for cve_id in detected_cves:
        info = CVE_REMEDIATION.get(cve_id)
        if not info:
            continue

        body += "-" * 50 + "\n"
        body += f"[{cve_id}] {info['name']}\n"
        body += f"  심각도 : {info['severity']}\n"
        body += f"  설명   : {info['description']}\n"
        body += f"  영향   : {info['impact']}\n\n"
        body += "  조치 방법:\n"
        for step in info["remediation"]:
            body += f"    - {step}\n"
        body += "\n  참고 자료:\n"
        for ref in info["references"]:
            body += f"    - {ref}\n"
        body += "\n"

    body += "=" * 50 + "\n"
    body += "[즉시] 항목부터 우선 조치하시기 바랍니다.\n"
    body += "=" * 50

    # 이메일 구성
    msg = MIMEMultipart()
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = receiver_email
    msg["Subject"] = f"[보안경고] 취약점 {len(detected_cves)}개 탐지 - 즉시 조치 필요"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # 전송
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"\n[+] 이메일 전송 성공 -> {receiver_email}")
    except Exception as e:
        print(f"\n[!] 이메일 전송 실패: {e}")


# ─────────────────────────────────────────
# 실행
# ─────────────────────────────────────────

if __name__ == "__main__":
    TARGET_IP = "127.0.0.1"
    NUCLEI_TARGETS = [
        "http://127.0.0.1:9080",   # Log4Shell
        "http://127.0.0.1:9081",   # SambaCry Web UI
        "http://127.0.0.1:9082",   # SSH Enum Web UI
    ]

    TARGET_TEMPLATES = {
        "http://127.0.0.1:9080": "templates/log4shell.yaml",
        "http://127.0.0.1:9081": "templates/sambacry.yaml",
        "http://127.0.0.1:9082": "templates/ssh-enum.yaml",
    }

    # 1. OS 추정
    print("=" * 60)
    print("       OS 추정 (TTL 기반)")
    print("=" * 60)
    ttl, os_guess = get_ttl(TARGET_IP)
    print(f"[+] 추정 OS: {os_guess}")

    # 2. Nuclei CVE 스캔
    nuclei_results = run_nuclei_scan(NUCLEI_TARGETS)

    # 3. 결과 요약
    print_summary(ttl, os_guess, nuclei_results)

    # 4. 관리자 조치 보고서
    print_remediation_report(nuclei_results)

    # 5. 이메일 전송
    send_email_report(nuclei_results, "이메일아이디e@gmail.com")
