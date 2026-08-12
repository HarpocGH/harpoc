# sshd backend for the E2E harness. Serves the `ssh` context (a login shell
# running the demo command) and git-over-ssh (a bare repo under /srv). Host keys
# and authorized_keys are bind-mounted at runtime and installed with the modes
# sshd demands — a bind mount carries host ownership, exactly like the PKI certs
# in the database services.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash harpoc \
 && echo 'harpoc:harpoc-e2e' | chpasswd \
 && mkdir -p /run/sshd /home/harpoc/.ssh \
 && chmod 700 /home/harpoc/.ssh \
 && chown -R harpoc:harpoc /home/harpoc/.ssh
