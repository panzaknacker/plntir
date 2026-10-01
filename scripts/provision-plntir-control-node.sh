#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root.\n' >&2
    exit 1
fi
if [[ $# -lt 2 || $# -gt 3 ]]; then
    printf 'usage: %s BUNDLE_DIR OBSERVER_PUBLIC_KEY [SOURCE_CIDR]\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly OBSERVER_PUBLIC_KEY=$2
readonly SOURCE_CIDR=${3:-}
readonly OPERATOR_USER=admin
readonly OBSERVER_USER=macobserver
readonly CONTROL_GROUP=plntircontrol
readonly OBSERVER_HOME=/var/lib/plntir-observer
readonly SSHD_CONFIG=/etc/ssh/sshd_config.d/20-plntir-control-node.conf
readonly SSHD_OBSERVER=/etc/ssh/sshd_config.d/10-plntir-observer.conf
readonly SUDOERS_OBSERVER=/etc/sudoers.d/90-plntir-observer

required_files=(
    client/internal/collector/plntir-status-v2.sh
    config/sshd/20-plntir-control-node.conf
    control-node/bin/plntir-endpoint-check
    control-node/bin/plntir-security-collect
    control-node/bin/plntir-secure-archive-manage
    control-node/bin/plntir-observer-dispatch
    control-node/bin/plntir-endpoint-retrieve
    control-node/bin/plntir-control-plane-backup
    control-node/lib/managed-endpoint-config.sh
    control-node/sshd/10-plntir-observer.conf
    control-node/sudoers/90-plntir-observer
    control-node/systemd/plntir-endpoint-security.service
    control-node/systemd/plntir-endpoint-security.timer
    control-node/systemd/plntir-secure-archive-readiness.service
    control-node/systemd/plntir-secure-archive-readiness.timer
    control-node/systemd/plntir-secure-archive.service
    control-node/systemd/plntir-endpoint-health.service
    control-node/systemd/plntir-endpoint-health.timer
    control-node/systemd/plntir-control-plane-backup.service
    control-node/systemd/plntir-control-plane-backup.timer
)
for relative in "${required_files[@]}"; do
    [[ -f "${BUNDLE_DIR}/${relative}" ]] || {
        printf 'Missing bundle file: %s\n' "${relative}" >&2
        exit 66
    }
done
[[ -f ${OBSERVER_PUBLIC_KEY} ]] || {
    printf 'Observer public key not found: %s\n' "${OBSERVER_PUBLIC_KEY}" >&2
    exit 66
}
id "${OPERATOR_USER}" >/dev/null 2>&1 || {
    printf 'Operator account does not exist: %s\n' "${OPERATOR_USER}" >&2
    exit 67
}
OPERATOR_GROUP=$(id -gn "${OPERATOR_USER}")
readonly OPERATOR_GROUP
if [[ -n ${SOURCE_CIDR} && ! ${SOURCE_CIDR} =~ ^[A-Fa-f0-9:.,/-]+$ ]]; then
    printf 'Invalid SOURCE_CIDR syntax.\n' >&2
    exit 64
fi

mapfile -t public_key_lines < <(/usr/bin/awk 'NF && $1 !~ /^#/' "${OBSERVER_PUBLIC_KEY}")
[[ ${#public_key_lines[@]} -eq 1 ]] || {
    printf 'Observer key file must contain exactly one public key.\n' >&2
    exit 65
}
readonly PUBLIC_KEY=${public_key_lines[0]}
[[ ${PUBLIC_KEY} =~ ^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com)[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || {
    printf 'Unsupported or malformed observer public key.\n' >&2
    exit 65
}
/usr/bin/ssh-keygen -l -f "${OBSERVER_PUBLIC_KEY}" >/dev/null

observer_existed=false
current_observer_home=''
if id "${OBSERVER_USER}" >/dev/null 2>&1; then
    observer_existed=true
    current_observer_home=$(/usr/bin/getent passwd "${OBSERVER_USER}" | /usr/bin/cut -d: -f6)
    [[ ${current_observer_home} == /var/lib/* &&
        -d ${current_observer_home} && ! -L ${current_observer_home} ]] || {
        printf 'Existing observer account has an unsafe home directory.\n' >&2
        exit 77
    }
fi

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}
install -d -m 0700 "${BACKUP_DIR}"
if [[ ${observer_existed} == true ]]; then
    /usr/bin/getent passwd "${OBSERVER_USER}" >"${BACKUP_DIR}/observer-passwd.before.txt"
    /bin/cp -a "${current_observer_home}" "${BACKUP_DIR}/observer-home.before"
    /bin/chmod 0600 "${BACKUP_DIR}/observer-passwd.before.txt"
fi

if ! /usr/bin/getent group "${CONTROL_GROUP}" >/dev/null; then
    /usr/sbin/groupadd --system "${CONTROL_GROUP}"
fi
if [[ ${observer_existed} != true ]]; then
    /usr/sbin/useradd \
        --system \
        --user-group \
        --create-home \
        --home-dir "${OBSERVER_HOME}" \
        --shell /bin/bash \
        --comment 'Plntir Observer Service' \
        "${OBSERVER_USER}"
elif [[ ${current_observer_home} != "${OBSERVER_HOME}" ]]; then
    [[ ! -e ${OBSERVER_HOME} ]] || {
        printf 'Target observer home already exists; refusing an ambiguous move.\n' >&2
        exit 77
    }
    /usr/sbin/usermod --home "${OBSERVER_HOME}" --move-home "${OBSERVER_USER}"
fi
/usr/sbin/usermod -a -G "${CONTROL_GROUP}" "${OPERATOR_USER}"
/usr/sbin/usermod -a -G "${CONTROL_GROUP}" "${OBSERVER_USER}"
/usr/sbin/usermod --comment 'Plntir Observer Service' "${OBSERVER_USER}"
passwd -l "${OBSERVER_USER}" >/dev/null

for target in \
    "${SSHD_CONFIG}" \
    "${SSHD_OBSERVER}" \
    "${SUDOERS_OBSERVER}" \
    /etc/systemd/system/plntir-endpoint-health.service \
    /etc/systemd/system/plntir-endpoint-health.timer \
    /etc/systemd/system/plntir-endpoint-security.service \
    /etc/systemd/system/plntir-endpoint-security.timer \
    /etc/systemd/system/plntir-secure-archive-readiness.service \
    /etc/systemd/system/plntir-secure-archive-readiness.timer \
    /etc/systemd/system/plntir-secure-archive.service \
    /etc/systemd/system/plntir-control-plane-backup.service \
    /etc/systemd/system/plntir-control-plane-backup.timer \
    /opt/plntir/bin/plntir-endpoint-check \
    /opt/plntir/bin/plntir-security-collect \
    /opt/plntir/bin/plntir-secure-archive-manage \
    /opt/plntir/bin/plntir-endpoint-retrieve \
    /opt/plntir/bin/plntir-control-plane-backup \
    /opt/plntir/lib/managed-endpoint-config.sh; do
    if [[ -e ${target} ]]; then
        install -D -m 0600 "${target}" "${BACKUP_DIR}${target}"
    fi
done

install -d -o root -g "${CONTROL_GROUP}" -m 0750 \
    /opt/plntir \
    /opt/plntir/bin \
    /opt/plntir/lib \
    /var/lib/plntir
install -d -o root -g "${CONTROL_GROUP}" -m 0750 /etc/plntir
install -d -o root -g root -m 0700 /var/lib/plntir/backup
install -d -o "${OPERATOR_USER}" -g "${CONTROL_GROUP}" -m 0750 \
    /var/lib/plntir/monitor \
    /var/lib/plntir/monitor/security \
    /var/lib/plntir/retrieved

chgrp -R "${CONTROL_GROUP}" /var/lib/plntir
find /var/lib/plntir -type d -exec chmod 0750 {} +
find /var/lib/plntir -type f -exec chmod 0640 {} +
install -d -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0700 \
    /var/lib/plntir/archive-gnupg
chown -R "${OPERATOR_USER}:${OPERATOR_GROUP}" /var/lib/plntir/archive-gnupg
find /var/lib/plntir/archive-gnupg -type d -exec chmod 0700 {} +
find /var/lib/plntir/archive-gnupg -type f -exec chmod 0600 {} +

install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE_DIR}/control-node/bin/plntir-endpoint-check" \
    "${BUNDLE_DIR}/control-node/bin/plntir-security-collect" \
    "${BUNDLE_DIR}/control-node/bin/plntir-secure-archive-manage" \
    "${BUNDLE_DIR}/control-node/bin/plntir-endpoint-retrieve" \
    "${BUNDLE_DIR}/control-node/bin/plntir-control-plane-backup" \
    "${BUNDLE_DIR}/control-node/bin/plntir-observer-dispatch" \
    /opt/plntir/bin/
install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE_DIR}/client/internal/collector/plntir-status-v2.sh" \
    /opt/plntir/bin/status-v2
install -o root -g "${CONTROL_GROUP}" -m 0640 \
    "${BUNDLE_DIR}/control-node/lib/managed-endpoint-config.sh" \
    /opt/plntir/lib/managed-endpoint-config.sh

install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-endpoint-health.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-endpoint-health.timer" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-endpoint-security.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-endpoint-security.timer" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive-readiness.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive-readiness.timer" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.timer" \
    /etc/systemd/system/
install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/config/sshd/20-plntir-control-node.conf" \
    "${SSHD_CONFIG}"
install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/sshd/10-plntir-observer.conf" \
    "${SSHD_OBSERVER}"
install -o root -g root -m 0440 \
    "${BUNDLE_DIR}/control-node/sudoers/90-plntir-observer" \
    "${SUDOERS_OBSERVER}"

/usr/sbin/visudo -cf /etc/sudoers
/usr/sbin/sshd -t

install -d -o "${OBSERVER_USER}" -g "${OBSERVER_USER}" -m 0700 \
    "${OBSERVER_HOME}/.ssh"
authorized_key_options=restrict
if [[ -n ${SOURCE_CIDR} ]]; then
    authorized_key_options="from=\"${SOURCE_CIDR}\",restrict"
fi
key_tmp=$(/usr/bin/mktemp "${OBSERVER_HOME}/.ssh/.authorized_keys.XXXXXX")
trap '/bin/rm -f "${key_tmp}"' EXIT
printf '%s %s\n' "${authorized_key_options}" "${PUBLIC_KEY}" >"${key_tmp}"
chown "${OBSERVER_USER}:${OBSERVER_USER}" "${key_tmp}"
chmod 0600 "${key_tmp}"
mv -f "${key_tmp}" "${OBSERVER_HOME}/.ssh/authorized_keys"
trap - EXIT

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl disable --now plntir-secure-archive-readiness.timer \
    >/dev/null 2>&1 || true
/usr/bin/systemctl stop plntir-secure-archive-readiness.service \
    >/dev/null 2>&1 || true
/usr/bin/systemctl enable --now \
    plntir-endpoint-health.timer \
    plntir-endpoint-security.timer
if ! readiness_timer_state=$(/usr/bin/systemctl show \
    --property=LoadState --property=ActiveState -- plntir-secure-archive-readiness.timer); then
    printf 'Cannot query archive readiness timer state.\n' >&2
    exit 77
fi
case ${readiness_timer_state} in
$'LoadState=loaded\nActiveState=inactive' | $'ActiveState=inactive\nLoadState=loaded') ;;
*)
    printf 'Archive readiness timer is not loaded and inactive.\n' >&2
    exit 77
    ;;
esac
if ! readiness_service_state=$(/usr/bin/systemctl show \
    --property=LoadState --property=ActiveState -- plntir-secure-archive-readiness.service); then
    printf 'Cannot query archive readiness service state.\n' >&2
    exit 77
fi
case ${readiness_service_state} in
$'LoadState=loaded\nActiveState=inactive' | $'ActiveState=inactive\nLoadState=loaded') ;;
*)
    printf 'Archive readiness service is not loaded and inactive.\n' >&2
    exit 77
    ;;
esac
/usr/bin/systemctl reload ssh

printf 'Plntir Control Node monitoring and forced-command observer installed.\n'
printf 'All-user archive readiness is on-demand; no scheduled /Users scan was enabled.\n'
printf 'Backup: %s\n' "${BACKUP_DIR}"
printf 'Verify before changing firewall or the dashboard default profile.\n'
