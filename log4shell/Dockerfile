FROM ghcr.io/christophetd/log4shell-vulnerable-app:latest

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD curl -f http://localhost:8080/ || exit 1
