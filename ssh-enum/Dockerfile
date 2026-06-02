FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

# CVE-2018-15473: 사용자 열거 취약점 활성화를 위한 설정
# Ubuntu 16.04의 OpenSSH 7.2p2 — 취약한 버전
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# 테스트용 계정 생성 (열거 대상)
RUN useradd -m testuser  && echo "testuser:password123"  | chpasswd
RUN useradd -m admin     && echo "admin:admin123"         | chpasswd
RUN useradd -m developer && echo "developer:dev2024"      | chpasswd

COPY web_status.py /web_status.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 8082

CMD ["/entrypoint.sh"]
