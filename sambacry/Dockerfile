FROM debian:bullseye

RUN apt-get update && apt-get install -y \
    samba \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY web_status.py /web_status.py
COPY entrypoint.sh /entrypoint.sh

RUN mkdir -p /share && chmod 777 /share
RUN useradd -m sambacry && echo "sambacry:password" | chpasswd
RUN sed -i 's/\r//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 139 445 9081

CMD ["/entrypoint.sh"]
