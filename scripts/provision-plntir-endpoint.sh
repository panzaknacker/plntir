#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root from an authenticated Plntir administrator session.\n' >&2
    exit 1
fi
if [[ $# -ne 7 ]]; then
    printf 'usage: %s BUNDLE_DIR AGENT_USER MANAGED_USER LEGACY_SSH_USER PLNTIR_CONTROL_NODE_IP MONITOR_PUBLIC_KEY RESPONSE_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly AGENT_USER=$2
readonly MANAGED_USER=$3
readonly LEGACY_SSH_USER=$4
readonly PLNTIR_CONTROL_NODE_IP=$5
readonly MONITOR_PUBLIC_KEY=$6
readonly RESPONSE_PUBLIC_KEY=$7
readonly EXPORT_GROUP=plntirarchive
readonly SSHD_TARGET=/etc/ssh/sshd_config.d/90-plntir.conf
readonly SUDOERS_TARGET=/etc/sudoers.d/90-plntir

[[ ${AGENT_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${AGENT_USER} == -* ]] || exit 64
[[ ${MANAGED_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${MANAGED_USER} == -* ]] || exit 64
[[ ${LEGACY_SSH_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${LEGACY_SSH_USER} == -* ]] || exit 64
[[ ${PLNTIR_CONTROL_NODE_IP} =~ ^[A-Fa-f0-9:./]+$ ]] || exit 64
id "${AGENT_USER}" >/dev/null 2>&1 || {
    printf 'Create the standard agent account first: %s\n' "${AGENT_USER}" >&2
    exit 67
}
id "${MANAGED_USER}" >/dev/null 2>&1 || {
    printf 'Managed user does not exist: %s\n' "${MANAGED_USER}" >&2
    exit 67
}
id "${LEGACY_SSH_USER}" >/dev/null 2>&1 || {
    printf 'Legacy SSH user does not exist: %s\n' "${LEGACY_SSH_USER}" >&2
    exit 67
}
[[ ${AGENT_USER} != "${LEGACY_SSH_USER}" ]] || {
    printf 'Agent and legacy SSH accounts must be different.\n' >&2
    exit 64
}
if /usr/sbin/dseditgroup -o checkmember -m "${AGENT_USER}" admin 2>/dev/null | /usr/bin/grep -Fq 'yes '; then
    printf 'Agent account must not be an administrator.\n' >&2
    exit 77
fi

required_files=(
    mac/libexec/plntir-health-collector
    mac/libexec/plntir-monitor-dispatch
    mac/libexec/plntir-response-dispatch.in
    mac/libexec/plntir-response-status
    mac/libexec/plntir-security-collector
    mac/libexec/plntir-retrieval-export
    mac/libexec/plntir-retrieval-export.py.in
    mac/sshd/90-plntir-endpoint.conf.in
    mac/sudoers/90-plntir-endpoint.in
)
for relative in "${required_files[@]}"; do
    [[ -f "${BUNDLE_DIR}/${relative}" ]] || {
        printf 'Missing bundle file: %s\n' "${relative}" >&2
        exit 66
    }
done

validate_public_key() {
    local path=$1
    local key_type
    [[ -f ${path} ]] || return 1
    /usr/bin/ssh-keygen -l -f "${path}" >/dev/null
    [[ $(/usr/bin/awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' "${path}") -eq 1 ]]
    key_type=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $1; exit}' "${path}")
    [[ ${key_type} == ssh-ed25519 || ${key_type} == sk-ssh-ed25519@openssh.com ]]
}

ensure_protected_directory() {
    local path=$1
    local metadata
    if [[ -L ${path} || (-e ${path} && ! -d ${path}) ]]; then
        printf 'Unsafe directory path: %s\n' "${path}" >&2
        return 1
    fi
    if [[ ! -d ${path} ]]; then
        /usr/bin/install -d -o root -g wheel -m 0755 "${path}"
    fi
    metadata=$(/usr/bin/stat -f '%Su:%Sg:%Lp' "${path}")
    if [[ ${metadata} != root:wheel:755 ]]; then
        printf 'Unsafe directory ownership or mode: %s (%s)\n' \
            "${path}" "${metadata}" >&2
        return 1
    fi
}

validate_public_key "${MONITOR_PUBLIC_KEY}" || {
    printf 'Invalid monitor public key.\n' >&2
    exit 65
}
validate_public_key "${RESPONSE_PUBLIC_KEY}" || {
    printf 'Invalid response public key.\n' >&2
    exit 65
}
monitor_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${MONITOR_PUBLIC_KEY}")
response_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${RESPONSE_PUBLIC_KEY}")
[[ ${monitor_blob} != "${response_blob}" ]] || {
    printf 'Monitor and response keys must be different.\n' >&2
    exit 65
}
MONITOR_KEY=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print; exit}' "${MONITOR_PUBLIC_KEY}")
readonly MONITOR_KEY
RESPONSE_KEY=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print; exit}' "${RESPONSE_PUBLIC_KEY}")
readonly RESPONSE_KEY
AGENT_GROUP=$(id -gn "${AGENT_USER}")
readonly AGENT_GROUP
AGENT_HOME=$(/usr/bin/dscl . -read "/Users/${AGENT_USER}" NFSHomeDirectory | /usr/bin/awk '{print $2}')
readonly AGENT_HOME
MANAGED_HOME=$(/usr/bin/dscl . -read "/Users/${MANAGED_USER}" NFSHomeDirectory | /usr/bin/awk '{print $2}')
readonly MANAGED_HOME
[[ ${AGENT_HOME} == /Users/* ]] || {
    printf 'Unexpected agent home: %s\n' "${AGENT_HOME}" >&2
    exit 77
}
[[ ${MANAGED_HOME} == /Users/* ]] || {
    printf 'Unexpected managed home: %s\n' "${MANAGED_HOME}" >&2
    exit 77
}

if ! /usr/bin/dscl . -read "/Groups/${EXPORT_GROUP}" >/dev/null 2>&1; then
    /usr/sbin/dseditgroup -o create "${EXPORT_GROUP}"
fi
/usr/sbin/dseditgroup -o edit -a "${AGENT_USER}" -t user "${EXPORT_GROUP}"
/usr/sbin/dseditgroup -o edit -a "${MANAGED_USER}" -t user "${EXPORT_GROUP}"
/usr/sbin/dseditgroup -o edit -a "${AGENT_USER}" -t user com.apple.access_ssh
/usr/sbin/dseditgroup -o edit -a "${LEGACY_SSH_USER}" -t user com.apple.access_ssh

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}
install -d -m 0700 "${BACKUP_DIR}"
/usr/bin/dscl . -read "/Users/${AGENT_USER}" RealName \
    >"${BACKUP_DIR}/agent-realname.before.txt" 2>&1 || true
/usr/bin/dscl . -read "/Users/${LEGACY_SSH_USER}" RealName \
    >"${BACKUP_DIR}/recovery-realname.before.txt" 2>&1 || true
/bin/chmod 0600 \
    "${BACKUP_DIR}/agent-realname.before.txt" \
    "${BACKUP_DIR}/recovery-realname.before.txt"
for target in \
    "${SSHD_TARGET}" \
    "${SUDOERS_TARGET}" \
    /usr/local/libexec/plntir-health-collector \
    /usr/local/libexec/plntir-monitor-dispatch \
    /usr/local/libexec/plntir-response-dispatch \
    /usr/local/libexec/plntir-response-status \
    /usr/local/libexec/plntir-security-collector \
    /usr/local/libexec/plntir-retrieval-export \
    /usr/local/libexec/plntir-retrieval-export.py; do
    if [[ -e ${target} ]]; then
        install -m 0600 "${target}" "${BACKUP_DIR}/$(printf '%s' "${target}" | /usr/bin/tr '/' '_')"
    fi
done

tmpdir=$(/usr/bin/mktemp -d /private/tmp/plntir.XXXXXX)
trap '/bin/rm -rf "${tmpdir}"' EXIT
/usr/bin/sed \
    -e "s/@AGENT_USER@/${AGENT_USER}/g" \
    -e "s/@MANAGED_USER@/${MANAGED_USER}/g" \
    "${BUNDLE_DIR}/mac/sudoers/90-plntir-endpoint.in" >"${tmpdir}/sudoers"
/usr/bin/sed \
    -e "s/@AGENT_USER@/${AGENT_USER}/g" \
    "${BUNDLE_DIR}/mac/sshd/90-plntir-endpoint.conf.in" >"${tmpdir}/sshd"
/usr/bin/sed \
    -e "s/@MANAGED_USER@/${MANAGED_USER}/g" \
    "${BUNDLE_DIR}/mac/libexec/plntir-response-dispatch.in" >"${tmpdir}/response-dispatch"
/usr/bin/sed \
    -e "s|@MANAGED_HOME@|${MANAGED_HOME}|g" \
    "${BUNDLE_DIR}/mac/libexec/plntir-retrieval-export.py.in" >"${tmpdir}/export.py"

/usr/sbin/visudo -cf "${tmpdir}/sudoers"
/usr/sbin/sshd -t -f "${tmpdir}/sshd"
/usr/bin/python3 -I -c 'import ast, pathlib; ast.parse(pathlib.Path(__import__("sys").argv[1]).read_text())' "${tmpdir}/export.py"

ensure_protected_directory /usr/local
ensure_protected_directory /usr/local/libexec
install -o root -g wheel -m 0755 \
    "${BUNDLE_DIR}/mac/libexec/plntir-health-collector" \
    "${BUNDLE_DIR}/mac/libexec/plntir-monitor-dispatch" \
    "${BUNDLE_DIR}/mac/libexec/plntir-response-status" \
    "${BUNDLE_DIR}/mac/libexec/plntir-security-collector" \
    "${BUNDLE_DIR}/mac/libexec/plntir-retrieval-export" \
    /usr/local/libexec/
install -o root -g wheel -m 0644 \
    "${tmpdir}/export.py" \
    /usr/local/libexec/plntir-retrieval-export.py
install -o root -g wheel -m 0755 \
    "${tmpdir}/response-dispatch" \
    /usr/local/libexec/plntir-response-dispatch
install -o root -g wheel -m 0440 "${tmpdir}/sudoers" "${SUDOERS_TARGET}"

/usr/sbin/visudo -cf /etc/sudoers

install -d -o "${AGENT_USER}" -g "${AGENT_GROUP}" -m 0700 "${AGENT_HOME}/.ssh"
key_tmp=$(/usr/bin/mktemp "${AGENT_HOME}/.ssh/.authorized_keys.XXXXXX")
trap '/bin/rm -rf "${tmpdir}"; /bin/rm -f "${key_tmp}"' EXIT
{
    printf 'from="%s",restrict,command="/usr/local/libexec/plntir-monitor-dispatch" %s\n' \
        "${PLNTIR_CONTROL_NODE_IP}" "${MONITOR_KEY}"
    printf 'from="%s",restrict,command="/usr/local/libexec/plntir-response-dispatch" %s\n' \
        "${PLNTIR_CONTROL_NODE_IP}" "${RESPONSE_KEY}"
} >"${key_tmp}"
chown "${AGENT_USER}:${AGENT_GROUP}" "${key_tmp}"
chmod 0600 "${key_tmp}"
mv -f "${key_tmp}" "${AGENT_HOME}/.ssh/authorized_keys"

install -d -o "${MANAGED_USER}" -g "${EXPORT_GROUP}" -m 2770 \
    /Users/Shared/.plntir/archive/retrievals

install -o root -g wheel -m 0644 "${tmpdir}/sshd" "${SSHD_TARGET}"
if ! /usr/sbin/sshd -t; then
    readonly SSHD_BACKUP="${BACKUP_DIR}/_etc_ssh_sshd_config.d_90-plntir.conf"
    if [[ -f ${SSHD_BACKUP} ]]; then
        install -o root -g wheel -m 0644 "${SSHD_BACKUP}" "${SSHD_TARGET}"
    else
        /bin/rm -f "${SSHD_TARGET}"
    fi
    /usr/sbin/sshd -t || true
    printf 'sshd validation failed; previous policy restored.\n' >&2
    exit 78
fi
trap - EXIT
/bin/rm -rf "${tmpdir}"

/usr/bin/dscl . -create "/Users/${AGENT_USER}" RealName 'Plntir Endpoint Agent'
/usr/bin/dscl . -create "/Users/${LEGACY_SSH_USER}" RealName 'Plntir Recovery Administrator'

printf 'Plntir Endpoint Agent monitor and response dispatchers installed for %s.\n' "${AGENT_USER}"
printf 'Backup: %s\n' "${BACKUP_DIR}"
printf 'Legacy SSH access for %s was retained for rollback.\n' "${LEGACY_SSH_USER}"
printf 'Test both new keys from the Plntir Control Node before ending the administrator session.\n'
