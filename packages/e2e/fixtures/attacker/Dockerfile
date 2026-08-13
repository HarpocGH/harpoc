# Exfiltration sink for the two-arm attack scenarios (C-3). No dependencies
# beyond Node's own https module, so the image needs no install step and builds
# offline.
FROM node:22-alpine

COPY server.mjs /srv/server.mjs

EXPOSE 8444

# The private key arrives on a read-only bind mount carrying the host's
# ownership and mode 600; the echo-https and database services read theirs the
# same way, and this container holds nothing but fixture material.
USER root

CMD ["node", "/srv/server.mjs"]
