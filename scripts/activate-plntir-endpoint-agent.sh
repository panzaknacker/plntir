#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi
if [[ $# -ne 6 ]]; then
    printf 'usage: %s AGENT_USER MANAGED_HOME MAC_MESH_IP MONITOR_PRIVATE_KEY RESPONSE_PRIVATE_KEY KNOWN_HOSTS\n' "$0" >&2
    exit 64
fi

readonly AGENT_USER=$1
readonly MANAGED_HOME=$2
readonly MAC_MESH_IP=$3
readonly MONITOR_SOURCE=$4
readonly RESPONSE_SOURCE=$5
readonly HOST_KEYS_SOURCE=$6
readonly OPERATOR_USER=admin
readonly CONTROL_GROUP=plntircontrol
readonly OPERATOR_HOME=/home/admin
readonly MONITOR_DEST=${OPERATOR_HOME}/.ssh/plntir_endpoint_monitor_ed25519
readonly RESPONSE_DEST=${OPERATOR_HOME}/.ssh/plntir_endpoint_response_ed25519
readonly HOST_KEYS_DEST=${OPERATOR_HOME}/.ssh/plntir_endpoint_known_hosts
readonly CONFIG_DIR=/etc/plntir
readonly CONFIG=${CONFIG_DIR}/managed-endpoint.conf
readonly CONFIG_LOADER=/opt/plntir/lib/managed-endpoint-config.sh

[[ ${AGENT_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${AGENT_USER} == -* ]] || {
    printf 'Invalid agent user.\n' >&2
    exit 64
}
[[ ${MANAGED_HOME} =~ ^/Users/[A-Za-z0-9._-]+$ ]] || {
    printf 'Managed home must be one direct child of /Users.\n' >&2
    exit 64
}
[[ ${MAC_MESH_IP} =~ ^[A-Fa-f0-9:.]+$ ]] || {
    printf 'Invalid mesh address syntax.\n' >&2
    exit 64
}
id "${OPERATOR_USER}" >/dev/null 2>&1 || exit 67
/usr/bin/getent group "${CONTROL_GROUP}" >/dev/null || exit 67
[[ -r ${CONFIG_LOADER} ]] || {
    printf 'Run provision-plntir-control-node.sh first.\n' >&2
    exit 69
}
for service in plntir-endpoint-health.service plntir-endpoint-security.service; do
    /usr/bin/systemctl cat "${service}" >/dev/null || {
        printf 'Missing service: %s\n' "${service}" >&2
        exit 69
    }
done

validate_private_key() {
    local path=$1
    [[ -f ${path} && ! -L ${path} ]] || return 1
    /usr/bin/ssh-keygen -y -P '' -f "${path}"
}
monitor_public=$(validate_private_key "${MONITOR_SOURCE}") || {
    printf 'Monitor key must be a readable, unencrypted private key.\n' >&2
    exit 65
}
response_public=$(validate_private_key "${RESPONSE_SOURCE}") || {
    printf 'Response key must be a readable, unencrypted private key.\n' >&2
    exit 65
}
[[ ${monitor_public} != "${response_public}" ]] || {
    printf 'Monitor and response keys must be different.\n' >&2
    exit 65
}
[[ -f ${HOST_KEYS_SOURCE} && ! -L ${HOST_KEYS_SOURCE} ]] || {
    printf 'Known-hosts file is missing or unsafe.\n' >&2
    exit 65
}
/usr/bin/ssh-keygen -F "${MAC_MESH_IP}" -f "${HOST_KEYS_SOURCE}" >/dev/null || {
    printf 'Known-hosts file has no entry for %s.\n' "${MAC_MESH_IP}" >&2
    exit 65
}

OPERATOR_GROUP=$(id -gn "${OPERATOR_USER}")
readonly OPERATOR_GROUP
STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}-endpoint-agent
config_existed=false
monitor_existed=false
response_existed=false
host_keys_existed=false
[[ -e ${CONFIG} ]] && config_existed=true
[[ -e ${MONITOR_DEST} ]] && monitor_existed=true
[[ -e ${RESPONSE_DEST} ]] && response_existed=true
[[ -e ${HOST_KEYS_DEST} ]] && host_keys_existed=true

install -d -m 0700 "${BACKUP_DIR}"
for target in "${CONFIG}" "${MONITOR_DEST}" "${RESPONSE_DEST}" "${HOST_KEYS_DEST}"; do
    if [[ -e ${target} ]]; then
        install -m 0600 "${target}" "${BACKUP_DIR}/$(/usr/bin/basename "${target}")"
    fi
done

config_tmp=''
config_changed=false
activation_complete=false
restore_operator_file() {
    local target=$1
    local existed=$2
    if [[ ${existed} == true ]]; then
        install -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0600 \
            "${BACKUP_DIR}/$(/usr/bin/basename "${target}")" "${target}"
    else
        /bin/rm -f "${target}"
    fi
}
rollback() {
    local rc=$?
    trap - EXIT
    set +e
    restore_operator_file "${MONITOR_DEST}" "${monitor_existed}"
    restore_operator_file "${RESPONSE_DEST}" "${response_existed}"
    restore_operator_file "${HOST_KEYS_DEST}" "${host_keys_existed}"
    if [[ ${config_changed} == true ]]; then
        if [[ ${config_existed} == true ]]; then
            install -o root -g "${CONTROL_GROUP}" -m 0640 \
                "${BACKUP_DIR}/managed-endpoint.conf" "${CONFIG}"
        else
            /bin/rm -f "${CONFIG}"
        fi
        /usr/bin/systemctl start plntir-endpoint-health.service >/dev/null 2>&1
    fi
    [[ -z ${config_tmp} ]] || /bin/rm -f "${config_tmp}"
    if [[ ${activation_complete} != true ]]; then
        printf 'Activation failed; prior keys and transport configuration were restored.\n' >&2
    fi
    exit "${rc}"
}
trap rollback EXIT

install -d -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0700 "${OPERATOR_HOME}/.ssh"
install -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0600 "${MONITOR_SOURCE}" "${MONITOR_DEST}"
install -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0600 "${RESPONSE_SOURCE}" "${RESPONSE_DEST}"
install -o "${OPERATOR_USER}" -g "${OPERATOR_GROUP}" -m 0600 "${HOST_KEYS_SOURCE}" "${HOST_KEYS_DEST}"

readonly TARGET=${AGENT_USER}@${MAC_MESH_IP}
ssh_options=(
    -T
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o IdentitiesOnly=yes
    -o PasswordAuthentication=no
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${HOST_KEYS_DEST}"
)
monitor_ssh=(
    /usr/bin/timeout 120
    /usr/sbin/runuser -u "${OPERATOR_USER}" --
    /usr/bin/ssh "${ssh_options[@]}" -i "${MONITOR_DEST}" "${TARGET}"
)
response_ssh=(
    /usr/bin/timeout 120
    /usr/sbin/runuser -u "${OPERATOR_USER}" --
    /usr/bin/ssh "${ssh_options[@]}" -i "${RESPONSE_DEST}" "${TARGET}"
)

health=$("${monitor_ssh[@]}" health-v1)
/usr/bin/grep -Fq 'remote_login=reachable' <<<"${health}"
posture=$("${monitor_ssh[@]}" posture-v1)
/usr/bin/grep -Fq '### SECURITY' <<<"${posture}"
response_status=$("${response_ssh[@]}" response-status-v1)
/usr/bin/grep -Fq 'remote_login=' <<<"${response_status}"

install -d -o root -g "${CONTROL_GROUP}" -m 0750 "${CONFIG_DIR}"
config_tmp=$(/usr/bin/mktemp "${CONFIG_DIR}/.managed-endpoint.conf.XXXXXX")
{
    printf 'MAC_TRANSPORT=dispatch\n'
    printf 'MAC_TARGET=%s\n' "${TARGET}"
    printf 'MAC_MONITOR_KEY=%s\n' "${MONITOR_DEST}"
    printf 'MAC_RESPONSE_KEY=%s\n' "${RESPONSE_DEST}"
    printf 'MAC_HOST_KEYS=%s\n' "${HOST_KEYS_DEST}"
    printf 'MAC_MANAGED_HOME=%s\n' "${MANAGED_HOME}"
} >"${config_tmp}"
chown root:"${CONTROL_GROUP}" "${config_tmp}"
chmod 0640 "${config_tmp}"
config_changed=true
mv -f "${config_tmp}" "${CONFIG}"
config_tmp=''

/usr/sbin/runuser -u "${OPERATOR_USER}" -- /bin/bash -c \
    "source /opt/plntir/lib/managed-endpoint-config.sh; load_managed_mac_config; [[ \${MAC_TRANSPORT} == dispatch ]]"
/usr/bin/systemctl start plntir-endpoint-health.service
/usr/bin/systemctl start plntir-endpoint-security.service
/usr/bin/jq -e '.state == "online" and .ssh_rc == 0' \
    /var/lib/plntir/monitor/mac-latest.json >/dev/null
/usr/bin/jq -e '.posture_rc == 0 and .telemetry_rc == 0' \
    /var/lib/plntir/monitor/security-latest.json >/dev/null

activation_complete=true
trap - EXIT
printf 'Plntir Control Node-to-Mac transport switched to forced-command agent %s.\n' "${TARGET}"
printf 'Backup: %s\n' "${BACKUP_DIR}"
printf 'Keep the legacy Mac key until retrieval and a full monitoring interval pass.\n'
