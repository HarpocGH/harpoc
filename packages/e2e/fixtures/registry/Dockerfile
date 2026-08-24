# Docker registry backend for the v1.3 docker-registry context, with htpasswd
# auth BAKED into the image (the Task 14 rider): anonymous access answers 401,
# so a pull that succeeds through the vault proves the vault-authored
# credential helper was genuinely consulted rather than the registry being
# open. The bcrypt entry is generated at build time by httpd's htpasswd —
# registry:2 accepts only bcrypt — from the fleet constants
# (harpoc-docker:docker-e2e-pw) that backends.ts DOCKER_REGISTRY pins.
FROM httpd:2.4-alpine AS auth
RUN htpasswd -Bbc /htpasswd harpoc-docker docker-e2e-pw

FROM registry:2
COPY --from=auth /htpasswd /auth/htpasswd
ENV REGISTRY_AUTH=htpasswd \
    REGISTRY_AUTH_HTPASSWD_REALM=harpoc-e2e \
    REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd
