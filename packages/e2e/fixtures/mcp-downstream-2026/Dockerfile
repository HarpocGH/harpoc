# Downstream MCP server on the 2026-07-28 revision only (SDK v2, legacy rejected): the modern
# counterparty for the vault's pinned client, beside the 1.30.0 fixtures that stay the legacy ones.
#
# The SDK version is pinned exactly, not by range, so the image a Chapter 6
# evidence run was produced against is reproducible.
FROM node:22-alpine

WORKDIR /srv

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.mjs ./

EXPOSE 8092

CMD ["node", "/srv/server.mjs"]
