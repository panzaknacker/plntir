#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Mac.\n' >&2
    exit 1
fi
if [[ $(/usr/bin/uname -s) != Darwin ]]; then
    printf 'This provisioner only supports macOS.\n' >&2
    exit 69
fi
if [[ $# -ne 6 ]]; then
    printf 'usage: %s BUNDLE_DIR AGENT_USER BREAKGLASS_USER PLNTIR_CONTROL_NODE_IP ARCHIVE_PUBLIC_KEY BREAKGLASS_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly AGENT_USER=$2
readonly BREAKGLASS_USER=$3
readonly PLNTIR_CONTROL_NODE_IP=$4
readonly ARCHIVE_PUBLIC_KEY=$5
readonly BREAKGLASS_PUBLIC_KEY=$6
readonly HELPER_TARGET=/usr/local/libexec/plntir-secure-archive
readonly DISPATCH_TARGET=/usr/local/libexec/plntir-secure-archive-dispatch
readonly SUDOERS_TARGET=/etc/sudoers.d/91-plntir-secure-archive

for account in "${AGENT_USER}" "${BREAKGLASS_USER}"; do
    [[ ${account} =~ ^[A-Za-z0-9._-]+$ && ! ${account} == -* ]] || {
        printf 'Invalid account name: %s\n' "${account}" >&2
        exit 64
    }
done
[[ ${AGENT_USER} != "${BREAKGLASS_USER}" ]] || {
    printf 'Agent and break-glass accounts must be distinct.\n' >&2
    exit 64
}
[[ ${PLNTIR_CONTROL_NODE_IP} =~ ^[A-Fa-f0-9:.]+$ ]] || {
    printf 'Invalid Plntir Control Node address.\n' >&2
    exit 64
}

required_files=(
    mac/libexec/plntir-secure-archive
    mac/libexec/plntir-secure-archive-dispatch
    mac/sudoers/91-plntir-secure-archive.in
)
for relative in "${required_files[@]}"; do
    [[ -f ${BUNDLE_DIR}/${relative} && ! -L ${BUNDLE_DIR}/${relative} ]] || {
        printf 'Missing or unsafe bundle file: %s\n' "${relative}" >&2
        exit 66
    }
done

read_public_key() {
    local path=$1
    local line
    [[ -f ${path} && ! -L ${path} ]] || return 1
    line=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print; count++} END {if (count != 1) exit 1}' "${path}") || return 1
    /usr/bin/ssh-keygen -l -f "${path}" >/dev/null || return 1
    [[ ${line} =~ ^(ssh-ed25519)[[:space:]]+([A-Za-z0-9+/=]+)([[:space:]].*)?$ ]] || return 1
    printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
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

read -r archive_type archive_blob < <(read_public_key "${ARCHIVE_PUBLIC_KEY}") || {
    printf 'Archive key must contain one valid Ed25519 public key.\n' >&2
    exit 65
}
read -r breakglass_type breakglass_blob < <(read_public_key "${BREAKGLASS_PUBLIC_KEY}") || {
    printf 'Break-glass key must contain one valid Ed25519 public key.\n' >&2
    exit 65
}
[[ ${archive_blob} != "${breakglass_blob}" ]] || {
    printf 'Archive and break-glass keys must be distinct.\n' >&2
    exit 65
}

/usr/bin/id "${AGENT_USER}" >/dev/null
/usr/bin/id "${BREAKGLASS_USER}" >/dev/null
if /usr/sbin/dseditgroup -o checkmember -m "${AGENT_USER}" admin 2>/dev/null | /usr/bin/grep -Fq 'yes '; then
    printf 'Restricted agent unexpectedly has administrator rights.\n' >&2
    exit 77
fi
/usr/sbin/dseditgroup -o checkmember -m "${BREAKGLASS_USER}" admin 2>/dev/null | /usr/bin/grep -Fq 'yes ' || {
    printf 'Break-glass account is not an administrator.\n' >&2
    exit 77
}
token_status=$(/usr/sbin/sysadminctl -secureTokenStatus "${BREAKGLASS_USER}" 2>&1 || true)
/usr/bin/grep -Fq 'ENABLED' <<<"${token_status}" || {
    printf 'Break-glass account has no Secure Token.\n' >&2
    exit 77
}

AGENT_HOME=$(/usr/bin/dscl . -read "/Users/${AGENT_USER}" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
BREAKGLASS_HOME=$(/usr/bin/dscl . -read "/Users/${BREAKGLASS_USER}" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
readonly AGENT_HOME BREAKGLASS_HOME
for home in "${AGENT_HOME}" "${BREAKGLASS_HOME}"; do
    [[ ${home} == /Users/* && ${home} != /Users/Shared && -d ${home} && ! -L ${home} ]] || {
        printf 'Unsafe account home: %s\n' "${home}" >&2
        exit 77
    }
    [[ -d ${home}/.ssh && ! -L ${home}/.ssh ]] || {
        printf 'Missing or unsafe SSH directory: %s/.ssh\n' "${home}" >&2
        exit 77
    }
    [[ ! -L ${home}/.ssh/authorized_keys ]] || {
        printf 'Refusing authorized_keys symlink: %s\n' "${home}" >&2
        exit 77
    }
done
readonly AGENT_KEYS=${AGENT_HOME}/.ssh/authorized_keys
readonly BREAKGLASS_KEYS=${BREAKGLASS_HOME}/.ssh/authorized_keys
[[ -f ${AGENT_KEYS} ]] || {
    printf 'Agent authorized_keys is missing; install the base update first.\n' >&2
    exit 69
}
/usr/bin/grep -Fq 'command="/usr/local/libexec/plntir-monitor-dispatch"' "${AGENT_KEYS}" || {
    printf 'Agent monitor forced key is missing.\n' >&2
    exit 69
}
/usr/bin/grep -Fq 'command="/usr/local/libexec/plntir-response-dispatch"' "${AGENT_KEYS}" || {
    printf 'Agent response forced key is missing.\n' >&2
    exit 69
}

AGENT_GROUP=$(/usr/bin/id -gn "${AGENT_USER}")
BREAKGLASS_GROUP=$(/usr/bin/id -gn "${BREAKGLASS_USER}")
readonly AGENT_GROUP BREAKGLASS_GROUP
STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}-access-upgrade
tmpdir=$(/usr/bin/mktemp -d /private/var/tmp/plntir-access-upgrade.XXXXXX)
readonly tmpdir
/usr/bin/install -d -o root -g wheel -m 0700 "${BACKUP_DIR}"

helper_existed=false
dispatch_existed=false
sudoers_existed=false
agent_keys_existed=false
breakglass_keys_existed=false
[[ -e ${HELPER_TARGET} ]] && helper_existed=true
[[ -e ${DISPATCH_TARGET} ]] && dispatch_existed=true
[[ -e ${SUDOERS_TARGET} ]] && sudoers_existed=true
[[ -e ${AGENT_KEYS} ]] && agent_keys_existed=true
[[ -e ${BREAKGLASS_KEYS} ]] && breakglass_keys_existed=true

backup_file() {
    local source=$1
    local label=$2
    if [[ -e ${source} ]]; then
        /bin/cp -p "${source}" "${BACKUP_DIR}/${label}"
    fi
}
backup_file "${HELPER_TARGET}" helper
backup_file "${DISPATCH_TARGET}" dispatch
backup_file "${SUDOERS_TARGET}" sudoers
backup_file "${AGENT_KEYS}" agent-authorized_keys
backup_file "${BREAKGLASS_KEYS}" breakglass-authorized_keys
/usr/bin/dscl . -read "/Users/${AGENT_USER}" RealName \
    >"${BACKUP_DIR}/agent-realname.before.txt" 2>&1 || true
/usr/bin/dscl . -read "/Users/${BREAKGLASS_USER}" RealName \
    >"${BACKUP_DIR}/recovery-realname.before.txt" 2>&1 || true
/bin/chmod 0600 \
    "${BACKUP_DIR}/agent-realname.before.txt" \
    "${BACKUP_DIR}/recovery-realname.before.txt"

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

upgrade_complete=false
rollback() {
    local rc=$?
    trap - EXIT
    set +e
    restore_file "${HELPER_TARGET}" "${helper_existed}" helper root wheel 0755
    restore_file "${DISPATCH_TARGET}" "${dispatch_existed}" dispatch root wheel 0755
    restore_file "${SUDOERS_TARGET}" "${sudoers_existed}" sudoers root wheel 0440
    restore_file "${AGENT_KEYS}" "${agent_keys_existed}" agent-authorized_keys \
        "${AGENT_USER}" "${AGENT_GROUP}" 0600
    restore_file "${BREAKGLASS_KEYS}" "${breakglass_keys_existed}" breakglass-authorized_keys \
        "${BREAKGLASS_USER}" "${BREAKGLASS_GROUP}" 0600
    /bin/rm -rf "${tmpdir}"
    /usr/sbin/visudo -cf /etc/sudoers >/dev/null 2>&1 || true
    if [[ ${upgrade_complete} != true ]]; then
        printf 'Access upgrade failed; prior files were restored.\n' >&2
    fi
    exit "${rc}"
}
trap rollback EXIT

/usr/bin/sed -e "s/@AGENT_USER@/${AGENT_USER}/g" \
    "${BUNDLE_DIR}/mac/sudoers/91-plntir-secure-archive.in" >"${tmpdir}/sudoers"
/usr/sbin/visudo -cf "${tmpdir}/sudoers"

ensure_protected_directory /usr/local
ensure_protected_directory /usr/local/libexec
/usr/bin/install -o root -g wheel -m 0755 \
    "${BUNDLE_DIR}/mac/libexec/plntir-secure-archive" "${HELPER_TARGET}"
/usr/bin/install -o root -g wheel -m 0755 \
    "${BUNDLE_DIR}/mac/libexec/plntir-secure-archive-dispatch" "${DISPATCH_TARGET}"
/usr/bin/install -o root -g wheel -m 0440 "${tmpdir}/sudoers" "${SUDOERS_TARGET}"
/usr/sbin/visudo -cf /etc/sudoers

agent_tmp=$(/usr/bin/mktemp "${AGENT_HOME}/.ssh/.authorized_keys.XXXXXX")
/usr/bin/awk \
    -v blob="${archive_blob}" \
    -v marker='plntir-secure-archive' \
    -v dispatcher='command="/usr/local/libexec/plntir-secure-archive-dispatch"' \
    'index($0, blob) == 0 && index($0, marker) == 0 && index($0, dispatcher) == 0 {print}' \
    "${AGENT_KEYS}" >"${agent_tmp}"
printf 'from="%s",restrict,command="/usr/local/libexec/plntir-secure-archive-dispatch" %s %s plntir-secure-archive\n' \
    "${PLNTIR_CONTROL_NODE_IP}" "${archive_type}" "${archive_blob}" >>"${agent_tmp}"
/usr/sbin/chown "${AGENT_USER}:${AGENT_GROUP}" "${agent_tmp}"
/bin/chmod 0600 "${agent_tmp}"
/bin/mv -f "${agent_tmp}" "${AGENT_KEYS}"

breakglass_tmp=$(/usr/bin/mktemp "${BREAKGLASS_HOME}/.ssh/.authorized_keys.XXXXXX")
if [[ -f ${BREAKGLASS_KEYS} ]]; then
    /usr/bin/awk \
        -v blob="${breakglass_blob}" \
        -v marker='plntir-recovery-access' \
        'index($0, blob) == 0 && index($0, marker) == 0 {print}' \
        "${BREAKGLASS_KEYS}" >"${breakglass_tmp}"
fi
printf 'from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc %s %s plntir-recovery-access\n' \
    "${PLNTIR_CONTROL_NODE_IP}" "${breakglass_type}" "${breakglass_blob}" >>"${breakglass_tmp}"
/usr/sbin/chown "${BREAKGLASS_USER}:${BREAKGLASS_GROUP}" "${breakglass_tmp}"
/bin/chmod 0600 "${breakglass_tmp}"
/bin/mv -f "${breakglass_tmp}" "${BREAKGLASS_KEYS}"

/bin/chmod 0700 "${AGENT_HOME}/.ssh" "${BREAKGLASS_HOME}/.ssh"
/usr/sbin/chown "${AGENT_USER}:${AGENT_GROUP}" "${AGENT_HOME}/.ssh" "${AGENT_KEYS}"
/usr/sbin/chown "${BREAKGLASS_USER}:${BREAKGLASS_GROUP}" \
    "${BREAKGLASS_HOME}/.ssh" "${BREAKGLASS_KEYS}"

/usr/bin/dscl . -create "/Users/${AGENT_USER}" RealName 'Plntir Endpoint Agent'
/usr/bin/dscl . -create "/Users/${BREAKGLASS_USER}" RealName 'Plntir Recovery Administrator'

upgrade_complete=true
trap - EXIT
/bin/rm -rf "${tmpdir}"
printf 'Plntir Secure Access Upgrade installed.\n'
printf 'Backup: %s\n' "${BACKUP_DIR}"
printf 'The break-glass key still requires the local admin password for sudo.\n'
