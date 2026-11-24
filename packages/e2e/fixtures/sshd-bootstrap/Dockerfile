# The target host of the `ssh` `bootstrap` rows: a real sshd with password login
# on, a real sudo with its visudo, and accounts that start.sh makes at every
# start, so a recreated container is a freshly installed host again.
ARG BASE=ubuntu:24.04
FROM ${BASE}
ARG SUDO_PACKAGE=sudo
ARG SUDO_BANNER="Sudo version 1.9."
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server ${SUDO_PACKAGE} \
 && rm -rf /var/lib/apt/lists/* \
 && sudo --version | head -n 1 | grep -F "${SUDO_BANNER}" \
 && mkdir -p /run/sshd
COPY sshd_config /etc/ssh/sshd_config
COPY start.sh slow-sudo.sh /usr/local/sbin/
RUN chmod 755 /usr/local/sbin/start.sh /usr/local/sbin/slow-sudo.sh \
 && sed -i '1i auth optional pam_exec.so quiet /usr/local/sbin/slow-sudo.sh' /etc/pam.d/sudo
