#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi
if [[ $# -ne 5 ]]; then
    printf 'usage: %s BUNDLE_DIR AGENT_USER MAC_MESH_IP ARCHIVE_PRIVATE_KEY ARCHIVE_GPG_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly AGENT_USER=$2
readonly MAC_MESH_IP=$3
readonly ARCHIVE_SOURCE=$4
readonly RECIPIENT_SOURCE=$5
readonly OPERATOR_USER=admin
readonly OPERATOR_GROUP=admin
readonly CONTROL_GROUP=plntircontrol
readonly ARCHIVE_DEST=/home/admin/.ssh/plntir_endpoint_archive_ed25519
readonly GPG_HOME=/var/lib/plntir/archive-gnupg
readonly CONFIG=/etc/plntir/managed-endpoint.conf
readonly CONFIG_LOADER=/opt/plntir/lib/managed-endpoint-config.sh
readonly STATUS_COLLECTOR=/opt/plntir/bin/status-v2
readonly EXPORT_MANAGER=/opt/plntir/bin/plntir-secure-archive-manage
readonly SSHD_CONFIG=/etc/ssh/sshd_config.d/20-plntir-control-node.conf
readonly EXPORT_SERVICE=/etc/systemd/system/plntir-secure-archive-readiness.service
readonly EXPORT_TIMER=/etc/systemd/system/plntir-secure-archive-readiness.timer
readonly ARCHIVE_SERVICE=/etc/systemd/system/plntir-secure-archive.service

[[ ${AGENT_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${AGENT_USER} == -* ]] || exit 64
[[ ${MAC_MESH_IP} =~ ^[A-Fa-f0-9:.]+$ ]] || exit 64
[[ ${MAC_MESH_IP} == 100.101.0.2 ]] || {
    printf 'The hardened SSH profile currently permits only 100.101.0.2:22.\n' >&2
    exit 64
}

required_files=(
    client/internal/collector/plntir-status-v2.sh
    config/sshd/20-plntir-control-node.conf
    control-node/bin/plntir-secure-archive-manage
    control-node/lib/managed-endpoint-config.sh
    control-node/systemd/plntir-secure-archive-readiness.service
    control-node/systemd/plntir-secure-archive-readiness.timer
    control-node/systemd/plntir-secure-archive.service
)
for relative in "${required_files[@]}"; do
    [[ -f ${BUNDLE_DIR}/${relative} && ! -L ${BUNDLE_DIR}/${relative} ]] || {
        printf 'Missing or unsafe bundle file: %s\n' "${relative}" >&2
        exit 66
    }
done
[[ -r ${CONFIG_LOADER} && -r ${CONFIG} ]] || {
    printf 'Activate the base forced-command transport first.\n' >&2
    exit 69
}
/usr/bin/id "${OPERATOR_USER}" >/dev/null
/usr/bin/getent group "${CONTROL_GROUP}" >/dev/null

# load and preserve the currently working connection before replacing the loader.
# shellcheck source=/dev/null
source "${CONFIG_LOADER}"
load_managed_mac_config
readonly CURRENT_TRANSPORT=${MAC_TRANSPORT}
readonly CURRENT_TARGET=${MAC_TARGET}
readonly CURRENT_MONITOR_KEY=${MAC_MONITOR_KEY}
readonly CURRENT_RESPONSE_KEY=${MAC_RESPONSE_KEY}
readonly CURRENT_HOST_KEYS=${MAC_HOST_KEYS}
readonly CURRENT_MANAGED_HOME=${MAC_MANAGED_HOME}
[[ ${CURRENT_TRANSPORT} == dispatch && ${CURRENT_TARGET} == "${AGENT_USER}@${MAC_MESH_IP}" ]] || {
    printf 'Current forced-command target does not match the requested Mac.\n' >&2
    exit 69
}

validate_private_key() {
    local path=$1
    [[ -f ${path} && ! -L ${path} ]] || return 1
    /usr/bin/ssh-keygen -y -P '' -f "${path}"
}
archive_public=$(validate_private_key "${ARCHIVE_SOURCE}") || {
    printf 'Archive SSH key must be a readable, unencrypted private key.\n' >&2
    exit 65
}
monitor_public=$(/usr/bin/ssh-keygen -y -P '' -f "${CURRENT_MONITOR_KEY}")
response_public=$(/usr/bin/ssh-keygen -y -P '' -f "${CURRENT_RESPONSE_KEY}")
[[ ${archive_public} != "${monitor_public}" && ${archive_public} != "${response_public}" ]] || {
    printf 'Archive SSH key must differ from monitor and response keys.\n' >&2
    exit 65
}
/usr/bin/ssh-keygen -F "${MAC_MESH_IP}" -f "${CURRENT_HOST_KEYS}" >/dev/null || {
    printf 'Known-hosts file has no entry for the managed Mac.\n' >&2
    exit 65
}
[[ -f ${RECIPIENT_SOURCE} && ! -L ${RECIPIENT_SOURCE} ]] || {
    printf 'Archive GPG public key is missing or unsafe.\n' >&2
    exit 65
}

validate_home=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${validate_home}"' EXIT
/bin/chmod 0700 "${validate_home}"
/usr/bin/gpg --homedir "${validate_home}" --batch --import "${RECIPIENT_SOURCE}" >/dev/null 2>&1
recipient_fingerprint=$(/usr/bin/gpg --homedir "${validate_home}" --batch --with-colons \
    --fingerprint | /usr/bin/awk -F: '$1 == "fpr" && !found {print $10; found=1}')
[[ ${recipient_fingerprint} =~ ^[A-Fa-f0-9]{40,64}$ ]] || {
    printf 'Could not determine archive recipient fingerprint.\n' >&2
    exit 65
}
/usr/bin/gpg --homedir "${validate_home}" --batch --with-colons --list-keys |
    /usr/bin/awk -F: '$1 == "pub" || $1 == "sub" {if (index($12, "e")) found=1} END {exit !found}' || {
    printf 'Archive recipient key has no encryption capability.\n' >&2
    exit 65
}
if /usr/bin/gpg --homedir "${validate_home}" --batch --with-colons --list-secret-keys |
    /usr/bin/grep '^sec:' >/dev/null; then
    printf 'Recipient file unexpectedly contains a private key.\n' >&2
    exit 65
fi
/bin/rm -rf "${validate_home}"
trap - EXIT

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}-access-control-node
/usr/bin/install -d -m 0700 "${BACKUP_DIR}"

config_existed=false
loader_existed=false
collector_existed=false
manager_existed=false
sshd_existed=false
service_existed=false
timer_existed=false
archive_service_existed=false
archive_existed=false
gpg_existed=false
timer_was_enabled=false
timer_was_active=false
[[ -e ${CONFIG} ]] && config_existed=true
[[ -e ${CONFIG_LOADER} ]] && loader_existed=true
[[ -e ${STATUS_COLLECTOR} ]] && collector_existed=true
[[ -e ${EXPORT_MANAGER} ]] && manager_existed=true
[[ -e ${SSHD_CONFIG} ]] && sshd_existed=true
[[ -e ${EXPORT_SERVICE} ]] && service_existed=true
[[ -e ${EXPORT_TIMER} ]] && timer_existed=true
[[ -e ${ARCHIVE_SERVICE} ]] && archive_service_existed=true
[[ -e ${ARCHIVE_DEST} ]] && archive_existed=true
[[ -e ${GPG_HOME} ]] && gpg_existed=true
if /usr/bin/systemctl is-enabled --quiet plntir-secure-archive-readiness.timer; then
    timer_was_enabled=true
fi
if /usr/bin/systemctl is-active --quiet plntir-secure-archive-readiness.timer; then
    timer_was_active=true
fi

backup_file() {
    local target=$1
    local label=$2
    if [[ -e ${target} ]]; then
        /bin/cp -p "${target}" "${BACKUP_DIR}/${label}"
    fi
}
backup_file "${CONFIG}" config
backup_file "${CONFIG_LOADER}" loader
backup_file "${STATUS_COLLECTOR}" collector
backup_file "${EXPORT_MANAGER}" manager
backup_file "${SSHD_CONFIG}" sshd
backup_file "${EXPORT_SERVICE}" service
backup_file "${EXPORT_TIMER}" timer
backup_file "${ARCHIVE_SERVICE}" archive-service
backup_file "${ARCHIVE_DEST}" archive-key
if [[ ${gpg_existed} == true ]]; then
    /bin/cp -a "${GPG_HOME}" "${BACKUP_DIR}/archive-gnupg"
fi

restore_file() {
    local target=$1
    local existed=$2
    local backup=$3
    local owner=$4
    local group=$5
    local mode=$6
    if [[ ${existed} == true ]]; then
        /usr/bin/install -o "${owner}" -g "${group}" -m "${mode}" \
            "${BACKUP_DIR}/${backup}" "${target}"
    else
        /bin/rm -f "${target}"
    fi
}

config_tmp=''
activation_complete=false
rollback() {
    local rc=$?
    trap - EXIT
    set +e
    /usr/bin/systemctl disable --now plntir-secure-archive-readiness.timer >/dev/null 2>&1
    restore_file "${CONFIG}" "${config_existed}" config root "${CONTROL_GROUP}" 0640
    restore_file "${CONFIG_LOADER}" "${loader_existed}" loader root "${CONTROL_GROUP}" 0640
    restore_file "${STATUS_COLLECTOR}" "${collector_existed}" collector root "${CONTROL_GROUP}" 0750
    restore_file "${EXPORT_MANAGER}" "${manager_existed}" manager root "${CONTROL_GROUP}" 0750
    restore_file "${SSHD_CONFIG}" "${sshd_existed}" sshd root root 0644
    restore_file "${EXPORT_SERVICE}" "${service_existed}" service root root 0644
    restore_file "${EXPORT_TIMER}" "${timer_existed}" timer root root 0644
    restore_file "${ARCHIVE_SERVICE}" "${archive_service_existed}" archive-service root root 0644
    restore_file "${ARCHIVE_DEST}" "${archive_existed}" archive-key \
        "${OPERATOR_USER}" "${OPERATOR_GROUP}" 0600
    /bin/rm -rf "${GPG_HOME}"
    if [[ ${gpg_existed} == true ]]; then
        /bin/cp -a "${BACKUP_DIR}/archive-gnupg" "${GPG_HOME}"
    fi
    [[ -z ${config_tmp} ]] || /bin/rm -f "${config_tmp}"
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1
    /usr/bin/systemctl reload ssh >/dev/null 2>&1
    if [[ ${timer_was_enabled} == true ]]; then
        /usr/bin/systemctl enable plntir-secure-archive-readiness.timer >/dev/null 2>&1
    fi
    if [[ ${timer_was_active} == true ]]; then
        /usr/bin/systemctl start plntir-secure-archive-readiness.timer >/dev/null 2>&1
    fi
    if [[ ${activation_complete} != true ]]; then
        printf 'Plntir Control Node access activation failed; prior files were restored.\n' >&2
    fi
    exit "${rc}"
}
trap rollback EXIT

/usr/bin/install -o root -g "${CONTROL_GROUP}" -m 0640 \
    "${BUNDLE_DIR}/control-node/lib/managed-endpoint-config.sh" "${CONFIG_LOADER}"
/usr/bin/install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE_DIR}/client/internal/collector/plntir-status-v2.sh" "${STATUS_COLLECTOR}"
/usr/bin/install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE_DIR}/control-node/bin/plntir-secure-archive-manage" "${EXPORT_MANAGER}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/config/sshd/20-plntir-control-node.conf" "${SSHD_CONFIG}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive-readiness.service" "${EXPORT_SERVICE}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive-readiness.timer" "${EXPORT_TIMER}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-secure-archive.service" "${ARCHIVE_SERVICE}"
/usr/bin/install -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0600 \
    "${ARCHIVE_SOURCE}" "${ARCHIVE_DEST}"

/usr/bin/install -d -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0700 "${GPG_HOME}"
# the migration input can remain root-only: root opens the public key and the
# unprivileged operator-owned GPG process receives only its public bytes.
if ! /bin/cat "${RECIPIENT_SOURCE}" |
    /usr/sbin/runuser -u "${OPERATOR_USER}" -- \
        /usr/bin/gpg --homedir "${GPG_HOME}" --batch --import \
        >/dev/null 2>&1; then
    printf 'Could not import the public archive recipient as %s.\n' \
        "${OPERATOR_USER}" >&2
    exit 65
fi
if /usr/sbin/runuser -u "${OPERATOR_USER}" -- \
    /usr/bin/gpg --homedir "${GPG_HOME}" --batch --with-colons --list-secret-keys |
    /usr/bin/grep '^sec:' >/dev/null; then
    printf 'Private archive key material must never be installed on the Plntir Control Node.\n' >&2
    exit 65
fi

config_tmp=$(/usr/bin/mktemp /etc/plntir/.managed-endpoint.conf.XXXXXX)
{
    printf 'MAC_TRANSPORT=%s\n' "${CURRENT_TRANSPORT}"
    printf 'MAC_TARGET=%s\n' "${CURRENT_TARGET}"
    printf 'MAC_MONITOR_KEY=%s\n' "${CURRENT_MONITOR_KEY}"
    printf 'MAC_RESPONSE_KEY=%s\n' "${CURRENT_RESPONSE_KEY}"
    printf 'MAC_ARCHIVE_KEY=%s\n' "${ARCHIVE_DEST}"
    printf 'MAC_ARCHIVE_RECIPIENT=%s\n' "${recipient_fingerprint}"
    printf 'MAC_HOST_KEYS=%s\n' "${CURRENT_HOST_KEYS}"
    printf 'MAC_MANAGED_HOME=%s\n' "${CURRENT_MANAGED_HOME}"
} >"${config_tmp}"
/bin/chown root:"${CONTROL_GROUP}" "${config_tmp}"
/bin/chmod 0640 "${config_tmp}"
/bin/mv -f "${config_tmp}" "${CONFIG}"
config_tmp=''

# shellcheck disable=SC2016
/usr/sbin/runuser -u "${OPERATOR_USER}" -- /bin/bash -c \
    'source /opt/plntir/lib/managed-endpoint-config.sh; load_managed_mac_config; [[ -n ${MAC_ARCHIVE_KEY} && -n ${MAC_ARCHIVE_RECIPIENT} ]]'
/usr/sbin/sshd -t
/usr/sbin/sshd -T -C user=admin,host=localhost,addr=127.0.0.1 |
    /usr/bin/grep -Fx 'allowtcpforwarding local' >/dev/null
/usr/sbin/sshd -T -C user=admin,host=localhost,addr=127.0.0.1 |
    /usr/bin/grep -Fx 'permitopen 100.101.0.2:22 127.0.0.1:1337' >/dev/null
/usr/sbin/sshd -T -C user=macobserver,host=localhost,addr=127.0.0.1 |
    /usr/bin/grep -Fx 'disableforwarding yes' >/dev/null
/usr/bin/systemctl reload ssh

archive_ssh=(
    /usr/bin/timeout 1800
    /usr/sbin/runuser -u "${OPERATOR_USER}" --
    /usr/bin/ssh
    -T
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o IdentitiesOnly=yes
    -o PasswordAuthentication=no
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${CURRENT_HOST_KEYS}"
    -i "${ARCHIVE_DEST}"
    "${CURRENT_TARGET}"
)
set +e
"${archive_ssh[@]}" 'uname -a' >/dev/null 2>&1
denied_rc=$?
set -e
[[ ${denied_rc} -ne 0 ]] || {
    printf 'Archive SSH key unexpectedly accepted an arbitrary command.\n' >&2
    exit 77
}

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl disable --now plntir-secure-archive-readiness.timer \
    >/dev/null 2>&1 || true
/usr/bin/systemctl stop plntir-secure-archive-readiness.service \
    >/dev/null 2>&1 || true
/usr/sbin/runuser -u "${OPERATOR_USER}" -- \
    "${EXPORT_MANAGER}" --check >/dev/null
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
/usr/bin/jq -e \
    '.schema_version == 1 and (.state == "ready" or .state == "blocked" or .state == "unreachable" or .state == "failed")' \
    /var/lib/plntir/monitor/all-users-export.json >/dev/null

activation_complete=true
trap - EXIT
printf 'Plntir Control Node on-demand all-user export and local-key recovery proxy activated.\n'
printf 'Scheduled /Users readiness scans are disabled.\n'
printf 'Archive recipient: %s\n' "${recipient_fingerprint}"
printf 'Backup: %s\n' "${BACKUP_DIR}"
