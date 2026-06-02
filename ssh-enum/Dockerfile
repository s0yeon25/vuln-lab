FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

RUN useradd -m testuser  && echo "testuser:password123"  | chpasswd
RUN useradd -m admin     && echo "admin:admin123"         | chpasswd
RUN useradd -m developer && echo "developer:dev2024"      | chpasswd

COPY web_status.py /web_status.py
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22 9082

CMD ["/entrypoint.sh"]
