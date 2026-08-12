# TLS echo backend: the http context's demonstration target and the Phase 4
# response-channel-echo scenario's server. No dependencies beyond Node's own
# https module, so the image needs no install step and builds offline.
FROM node:22-alpine

COPY server.mjs /srv/server.mjs

EXPOSE 8443

# The private key arrives on a read-only bind mount carrying the host's
# ownership and mode 600; running as root is how the database services read
# theirs too, and this container holds nothing but fixture material.
USER root

CMD ["node", "/srv/server.mjs"]
