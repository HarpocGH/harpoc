FROM node:24-bookworm

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bubblewrap dbus-x11 git gnome-keyring keyutils libsecret-tools openssh-client procps rsync sudo \
  && rm -rf /var/lib/apt/lists/*

RUN npm install --global pnpm@10.11.0

RUN useradd --create-home --shell /bin/bash dev \
  && useradd --create-home --shell /bin/bash agent \
  && printf 'dev ALL=(ALL) NOPASSWD:ALL\n' >/etc/sudoers.d/dev \
  && chmod 0440 /etc/sudoers.d/dev \
  && install -d -o dev -g dev -m 0755 /work /pnpm-store

COPY linux/install-two-identity.sh /usr/local/sbin/install-two-identity.sh
RUN bash /usr/local/sbin/install-two-identity.sh agent \
  && bash /usr/local/sbin/install-two-identity.sh agent \
  && test "$(stat -c '%a %U:%G' /var/lib/harpoc /run/harpoc /run/harpoc/agent | tr '\n' ' ')" \
    = "700 harpoc:harpoc 750 harpoc:harpoc-clients 2750 harpoc:agent " \
  && id -nG agent | grep -qw harpoc-clients

USER dev
WORKDIR /work
