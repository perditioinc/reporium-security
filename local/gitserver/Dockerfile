# OSS, $0 local substitute for GitHub's git transport.
# Plain git daemon (git:// protocol), read-only upload-pack. No paid services.
FROM alpine:3.20

RUN apk add --no-cache git git-daemon

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9418
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
