FROM alpine:3.20
RUN apk add --no-cache socat
COPY serve.sh /serve.sh
RUN chmod +x /serve.sh
ENTRYPOINT ["/serve.sh"]
