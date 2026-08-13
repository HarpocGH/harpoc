# Tool-poisoning MCP server (§6.2.3): a real MCP server over Streamable HTTP
# whose tool DESCRIPTION carries the injection. Separate image from
# mcp-downstream on purpose — that service is a Phase 3 demonstration target and
# an attack fixture must not be able to change how a demonstration cell behaves.
#
# The SDK version is pinned exactly, not by range, so the image a Chapter 6
# evidence run was produced against is reproducible.
FROM node:22-alpine

WORKDIR /srv

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.mjs ./

EXPOSE 8091

CMD ["node", "/srv/server.mjs"]
