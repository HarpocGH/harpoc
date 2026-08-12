# Downstream MCP server over Streamable HTTP: the `mcp` context's demonstration
# target, and the counterparty for the vault's HTTP-transport proxy path
# (pinned dispatcher, redirects refused) that the stdio path never exercises.
#
# The SDK version is pinned exactly, not by range, so the image a Chapter 6
# evidence run was produced against is reproducible.
FROM node:22-alpine

WORKDIR /srv

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.mjs ./

EXPOSE 8090

CMD ["node", "/srv/server.mjs"]
