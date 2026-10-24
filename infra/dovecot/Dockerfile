FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends dovecot-imapd openssl ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 5000 vmail && useradd -u 5000 -g vmail -d /mail vmail && mkdir -p /mail && chown vmail:vmail /mail \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout /etc/dovecot/key.pem -out /etc/dovecot/cert.pem -subj /CN=localhost
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY oauth2.conf /etc/dovecot/oauth2.conf
EXPOSE 143 993
CMD ["dovecot", "-F"]
