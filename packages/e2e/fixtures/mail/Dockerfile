# SMTP + IMAP mail backend for the v1.3 smtp/imap contexts. No dependencies
# beyond Node's own net/tls modules, so the image needs no install step and
# builds offline — the same shape as the echo-https and attacker fixtures.
FROM node:22-alpine

COPY server.mjs /srv/server.mjs

EXPOSE 8465 8993

# The TLS key arrives on a read-only bind mount carrying the host's ownership
# and mode 600; running as root is how the database and echo-https services read
# theirs too, and this container holds nothing but fixture material.
USER root

CMD ["node", "/srv/server.mjs"]
