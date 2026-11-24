#!/bin/sh
set -eu
install -o root -g root -m 600 /bootstrap/hostkey /etc/ssh/ssh_host_ed25519_key
for u in plain rooted outside startup expired slow loose; do
  useradd -m -s /bin/bash "$u"
  printf '%s:%s\n' "$u" "$(cat /bootstrap/password)" | chpasswd
done
for u in plain rooted startup expired slow loose; do usermod -aG sudo "$u"; done
printf 'IFS= read -r harpoc_e2e_line\n' >/home/startup/.bashrc
chage -d 0 expired
chmod o+w /home/loose
exec /usr/sbin/sshd -D -e "$@"
