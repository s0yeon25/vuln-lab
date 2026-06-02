FROM debian:bullseye

RUN apt-get update && apt-get install -y samba && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf

RUN mkdir -p /share && chmod 777 /share
RUN useradd -m sambacry && echo "sambacry:password" | chpasswd

EXPOSE 139 445

CMD ["smbd", "--foreground", "--no-process-group"]