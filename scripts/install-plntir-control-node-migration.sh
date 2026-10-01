#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi
if [[ $(/usr/bin/uname -s) != Linux ]]; then
    printf 'This migration only supports the Linux Control Node.\n' >&2
    exit 69
fi
if [[ $# -lt 7 || $# -gt 8 ]]; then
    printf 'usage: %s BUNDLE_DIR OBSERVER_PUBLIC_KEY MONITOR_PRIVATE_KEY RESPONSE_PRIVATE_KEY ARCHIVE_PRIVATE_KEY ARCHIVE_GPG_PUBLIC_KEY ENDPOINT_KNOWN_HOSTS [--copy-legacy-retrieved]\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly OBSERVER_PUBLIC_KEY=$2
readonly MONITOR_PRIVATE_KEY=$3
readonly RESPONSE_PRIVATE_KEY=$4
readonly ARCHIVE_PRIVATE_KEY=$5
readonly ARCHIVE_GPG_PUBLIC_KEY=$6
readonly ENDPOINT_KNOWN_HOSTS=$7
readonly LEGACY_RETRIEVAL_ACTION=${8:-refuse}
readonly LEGACY_ETC=/etc/mac-control-plane
readonly LEGACY_OPT=/opt/mac-control-plane
readonly LEGACY_STATE=/var/lib/mac-control-plane
readonly MAC_MESH_IP=100.101.0.2
readonly MANAGED_HOME=/Users/plntir-operator
readonly AGENT_USER=macagent
readonly PLNTIR_HOSTNAME=plntir-control-node-01

case ${LEGACY_RETRIEVAL_ACTION} in
refuse | --copy-legacy-retrieved) ;;
*)
    printf 'Invalid legacy retrieval action.\n' >&2
    exit 64
    ;;
esac

for path in \
    "${BUNDLE_DIR}" \
    "${OBSERVER_PUBLIC_KEY}" \
    "${MONITOR_PRIVATE_KEY}" \
    "${RESPONSE_PRIVATE_KEY}" \
    "${ARCHIVE_PRIVATE_KEY}" \
    "${ARCHIVE_GPG_PUBLIC_KEY}" \
    "${ENDPOINT_KNOWN_HOSTS}"; do
    [[ -e ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe migration input: %s\n' "${path}" >&2
        exit 66
    }
done
[[ -d ${BUNDLE_DIR} ]] || exit 66
if [[ $(/usr/bin/stat -Lc %u "${BUNDLE_DIR}") -ne 0 ]]; then
    printf 'Migration bundle must be root-owned.\n' >&2
    exit 77
fi
unsafe_path=$(/usr/bin/find "${BUNDLE_DIR}" \( -perm -0020 -o -perm -0002 \) -print -quit)
if [[ -n ${unsafe_path} ]]; then
    printf 'Migration bundle contains a group/other-writable path: %s\n' "${unsafe_path}" >&2
    exit 77
fi

for key in "${MONITOR_PRIVATE_KEY}" "${RESPONSE_PRIVATE_KEY}" "${ARCHIVE_PRIVATE_KEY}"; do
    [[ -f ${key} && $(/usr/bin/stat -Lc %a "${key}") =~ ^[46]00$ ]] || {
        printf 'Private migration key has unsafe permissions: %s\n' "${key}" >&2
        exit 77
    }
    /usr/bin/ssh-keygen -y -P '' -f "${key}" >/dev/null
done
monitor_public=$(/usr/bin/ssh-keygen -y -P '' -f "${MONITOR_PRIVATE_KEY}")
response_public=$(/usr/bin/ssh-keygen -y -P '' -f "${RESPONSE_PRIVATE_KEY}")
archive_public=$(/usr/bin/ssh-keygen -y -P '' -f "${ARCHIVE_PRIVATE_KEY}")
[[ ${monitor_public} != "${response_public}" &&
    ${monitor_public} != "${archive_public}" &&
    ${response_public} != "${archive_public}" ]] || {
    printf 'Monitor, response, and archive SSH keys must be distinct.\n' >&2
    exit 65
}
/usr/bin/ssh-keygen -F "${MAC_MESH_IP}" -f "${ENDPOINT_KNOWN_HOSTS}" >/dev/null || {
    printf 'Endpoint known_hosts has no entry for %s.\n' "${MAC_MESH_IP}" >&2
    exit 65
}

if /usr/bin/systemctl is-active --quiet mac-all-users-export.service; then
    printf 'An existing all-user export is active; refusing migration.\n' >&2
    exit 75
fi
legacy_retrievals_present=false
if [[ -d ${LEGACY_STATE}/retrieved ]] &&
    [[ -n $(/usr/bin/find "${LEGACY_STATE}/retrieved" -type f -print -quit) ]]; then
    legacy_retrievals_present=true
    if [[ ${LEGACY_RETRIEVAL_ACTION} != --copy-legacy-retrieved ]]; then
        printf 'Existing retrieved artifacts require --copy-legacy-retrieved.\n' >&2
        exit 75
    fi
fi
readonly legacy_retrievals_present

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}-control-node-migration
/usr/bin/install -d -m 0700 "${BACKUP_DIR}"
/bin/hostname >"${BACKUP_DIR}/hostname.before.txt"
for path in /etc/hostname /etc/cloud/cloud.cfg.d/99-plntir-hostname.cfg; do
    if [[ -e ${path} ]]; then
        /bin/cp -a "${path}" "${BACKUP_DIR}/$(/usr/bin/basename "${path}").before"
    fi
done
if [[ -e ${LEGACY_ETC} ]]; then
    /bin/cp -a "${LEGACY_ETC}" "${BACKUP_DIR}/previous-etc"
fi
if [[ -e ${LEGACY_OPT} ]]; then
    /bin/cp -a "${LEGACY_OPT}" "${BACKUP_DIR}/previous-opt"
fi
/usr/bin/systemctl list-unit-files >"${BACKUP_DIR}/unit-files.before.txt"
/bin/chmod 0600 "${BACKUP_DIR}"/*.txt

migration_complete=false
stage=provision-control-node
on_exit() {
    local rc=$?
    trap - EXIT
    if [[ ${migration_complete} == true && ${rc} -eq 0 ]]; then
        printf 'Plntir Control Node migration completed successfully.\n'
    else
        printf 'Plntir Control Node migration failed during %s (rc=%d).\n' "${stage}" "${rc}" >&2
        printf 'Previous-generation timers were not intentionally disabled. Backup: %s\n' "${BACKUP_DIR}" >&2
    fi
    exit "${rc}"
}
trap on_exit EXIT

"${BUNDLE_DIR}/scripts/provision-plntir-control-node.sh" \
    "${BUNDLE_DIR}" \
    "${OBSERVER_PUBLIC_KEY}"

/usr/bin/systemctl stop \
    plntir-endpoint-health.timer \
    plntir-endpoint-security.timer \
    plntir-secure-archive-readiness.timer

stage=migrate-legacy-retrievals
if [[ ${legacy_retrievals_present} == true ]]; then
    readonly LEGACY_RETRIEVED_TARGET=/var/lib/plntir/retrieved/legacy-pre-plntir
    if [[ -e ${LEGACY_RETRIEVED_TARGET} ]]; then
        [[ -d ${LEGACY_RETRIEVED_TARGET} && ! -L ${LEGACY_RETRIEVED_TARGET} ]] || {
            printf 'Existing legacy retrieval target is unsafe.\n' >&2
            exit 77
        }
    else
        /usr/bin/install -d -o admin -g plntircontrol -m 0750 \
            "${LEGACY_RETRIEVED_TARGET}"
        /bin/cp -a "${LEGACY_STATE}/retrieved/." "${LEGACY_RETRIEVED_TARGET}/"
    fi
    /usr/bin/diff -qr "${LEGACY_STATE}/retrieved" "${LEGACY_RETRIEVED_TARGET}"
    /bin/chown -R admin:plntircontrol "${LEGACY_RETRIEVED_TARGET}"
    /usr/bin/find "${LEGACY_RETRIEVED_TARGET}" -type d -exec /bin/chmod 0750 {} +
    /usr/bin/find "${LEGACY_RETRIEVED_TARGET}" -type f -exec /bin/chmod 0640 {} +
    printf 'Legacy retrieved artifacts are copied and verified; originals are retained.\n'
fi

stage=migrate-monitoring-state
if [[ -d ${LEGACY_STATE}/monitor ]]; then
    /bin/cp -a "${LEGACY_STATE}/monitor/." /var/lib/plntir/monitor/
    /bin/chown -R admin:plntircontrol /var/lib/plntir/monitor
    /usr/bin/find /var/lib/plntir/monitor -type d -exec /bin/chmod 0750 {} +
    /usr/bin/find /var/lib/plntir/monitor -type f -exec /bin/chmod 0640 {} +
fi

stage=activate-endpoint-agent
"${BUNDLE_DIR}/scripts/activate-plntir-endpoint-agent.sh" \
    "${AGENT_USER}" \
    "${MANAGED_HOME}" \
    "${MAC_MESH_IP}" \
    "${MONITOR_PRIVATE_KEY}" \
    "${RESPONSE_PRIVATE_KEY}" \
    "${ENDPOINT_KNOWN_HOSTS}"

stage=activate-secure-archive
"${BUNDLE_DIR}/scripts/activate-plntir-secure-access.sh" \
    "${BUNDLE_DIR}" \
    "${AGENT_USER}" \
    "${MAC_MESH_IP}" \
    "${ARCHIVE_PRIVATE_KEY}" \
    "${ARCHIVE_GPG_PUBLIC_KEY}"

stage=brand-hostname
/usr/bin/install -d -m 0755 /etc/cloud/cloud.cfg.d
hostname_tmp=$(/usr/bin/mktemp /etc/cloud/cloud.cfg.d/.99-plntir-hostname.XXXXXX)
printf 'preserve_hostname: true\n' >"${hostname_tmp}"
/bin/chown root:root "${hostname_tmp}"
/bin/chmod 0644 "${hostname_tmp}"
/bin/mv -f "${hostname_tmp}" /etc/cloud/cloud.cfg.d/99-plntir-hostname.cfg
/usr/bin/hostnamectl set-hostname "${PLNTIR_HOSTNAME}"

stage=verify-plntir
/usr/bin/systemctl start \
    plntir-endpoint-health.timer \
    plntir-endpoint-security.timer
/usr/bin/systemctl disable --now plntir-secure-archive-readiness.timer \
    >/dev/null 2>&1 || true
/usr/bin/systemctl stop plntir-secure-archive-readiness.service \
    >/dev/null 2>&1 || true
"${BUNDLE_DIR}/scripts/verify-plntir-control-node.sh"
/usr/sbin/runuser -u macobserver -- /usr/bin/env SSH_ORIGINAL_COMMAND=status-v2 \
    /opt/plntir/bin/plntir-observer-dispatch |
    /usr/bin/jq -e '.schema_version == 2 and .node.hostname == "plntir-control-node-01"' >/dev/null

stage=disable-previous-timers
for unit in \
    mac-watchdog.timer \
    mac-security-collect.timer \
    mac-all-users-export-readiness.timer; do
    if /usr/bin/systemctl cat "${unit}" >/dev/null 2>&1; then
        /usr/bin/systemctl disable --now "${unit}"
    fi
done

migration_complete=true
trap - EXIT
printf 'Plntir Control Node migration completed successfully.\n'
printf 'Backup: %s\n' "${BACKUP_DIR}"
printf 'Previous-generation files were retained for rollback; their timers are disabled.\n'
