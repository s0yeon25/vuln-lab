FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server && rm -rf /var/lib/apt/lists/*

RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN useradd -m testuser && echo "testuser:password123" | chpasswd
RUN useradd -m admin && echo "admin:admin123" | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]