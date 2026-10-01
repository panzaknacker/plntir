#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root.\n' >&2
    exit 1
fi

readonly BUNDLE_DIR=${1:-/tmp/plntir-base}

for required in \
    scripts/provision-plntir-control-node-base.sh \
    scripts/verify-plntir-control-node-base.sh \
    config/apt/20auto-upgrades \
    config/apt/52plntir-unattended-upgrades \
    config/audit/50-plntir.rules \
    config/docker/daemon.json \
    config/fail2ban/sshd.local \
    config/nftables/nftables.conf \
    config/resolved/99-plntir-control-node.conf \
    config/sshd/20-plntir-control-node.conf \
    config/sysctl/99-plntir-control-node.conf; do
    [[ -f "${BUNDLE_DIR}/${required}" ]] || {
        printf 'Missing bundle file: %s\n' "${required}" >&2
        exit 1
    }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    acl \
    apparmor \
    apparmor-utils \
    auditd \
    audispd-plugins \
    ca-certificates \
    curl \
    docker-compose \
    docker.io \
    fail2ban \
    git \
    gnupg \
    jq \
    needrestart \
    nftables \
    rsync \
    shellcheck \
    unzip

install -d -m 0750 /opt/plntir /var/lib/plntir
install -d -m 0750 /opt/plntir/bin
install -m 0750 "${BUNDLE_DIR}/scripts/provision-plntir-control-node-base.sh" /opt/plntir/bin/provision-plntir-control-node-base
install -m 0750 "${BUNDLE_DIR}/scripts/verify-plntir-control-node-base.sh" /opt/plntir/bin/verify-plntir-control-node-base
install -d -m 0755 \
    /etc/apt/apt.conf.d \
    /etc/audit/rules.d \
    /etc/docker \
    /etc/fail2ban/jail.d \
    /etc/ssh/sshd_config.d \
    /etc/systemd/resolved.conf.d \
    /etc/sysctl.d

install -m 0644 "${BUNDLE_DIR}/config/apt/20auto-upgrades" \
    /etc/apt/apt.conf.d/20auto-upgrades
install -m 0644 \
    "${BUNDLE_DIR}/config/apt/52plntir-unattended-upgrades" \
    /etc/apt/apt.conf.d/52plntir-unattended-upgrades
install -m 0600 "${BUNDLE_DIR}/config/audit/50-plntir.rules" \
    /etc/audit/rules.d/50-plntir.rules
install -m 0644 "${BUNDLE_DIR}/config/docker/daemon.json" \
    /etc/docker/daemon.json
install -m 0644 "${BUNDLE_DIR}/config/fail2ban/sshd.local" \
    /etc/fail2ban/jail.d/sshd.local
install -m 0755 "${BUNDLE_DIR}/config/nftables/nftables.conf" \
    /etc/nftables.conf
install -m 0644 "${BUNDLE_DIR}/config/resolved/99-plntir-control-node.conf" \
    /etc/systemd/resolved.conf.d/99-plntir-control-node.conf
install -m 0644 "${BUNDLE_DIR}/config/sshd/20-plntir-control-node.conf" \
    /etc/ssh/sshd_config.d/20-plntir-control-node.conf
install -m 0644 "${BUNDLE_DIR}/config/sysctl/99-plntir-control-node.conf" \
    /etc/sysctl.d/99-plntir-control-node.conf

if ! swapon --show=NAME --noheadings --raw | grep -Fxq /swapfile; then
    if [[ ! -f /swapfile ]]; then
        fallocate -l 4G /swapfile
        chmod 0600 /swapfile
        mkswap /swapfile
    fi
    swapon /swapfile
fi
grep -Eq '^/swapfile[[:space:]]' /etc/fstab ||
    printf '/swapfile none swap sw 0 0\n' >>/etc/fstab

sshd -t
nft -c -f /etc/nftables.conf
sysctl --system
fail2ban-client -t
augenrules --check

systemctl enable --now apparmor auditd docker fail2ban nftables
systemctl restart systemd-resolved
systemctl restart docker
systemctl restart fail2ban
augenrules --load
systemctl reload ssh

printf 'Base provisioning complete. Keep SSH/22 open until the tunnel and recovery path are verified.\n'
