# git smart-HTTP backend for the E2E harness. Apache + git-http-backend behind
# basic auth so the vault's GIT_ASKPASS credential injection is genuinely
# exercised — a 401 on the /git/ location triggers the helper. A /redirect
# location 302s off-box for the H6a redirect-refusal arm. The credential baked
# into the htpasswd matches the harness GIT_HTTP constant.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 apache2-utils git \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod cgid alias env rewrite auth_basic authn_file authz_user \
 && htpasswd -bBc /etc/apache2/git-htpasswd harpoc git-e2e-pw

COPY git-http.conf /etc/apache2/conf-enabled/git-http.conf
