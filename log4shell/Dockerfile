FROM ghcr.io/christophetd/log4shell-vulnerable-app:latest

USER root
RUN apk add --no-cache python3

COPY web_status.py /web_status.py

EXPOSE 9080

CMD sh -c "SERVER_PORT=18080 java -jar /app/spring-boot-application.jar & python3 /web_status.py"
