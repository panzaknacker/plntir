#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root from an authenticated Plntir administrator session.\n' >&2
    exit 1
fi
if [[ $(/usr/bin/uname -s) != Darwin ]]; then
    printf 'This installer only supports macOS.\n' >&2
    exit 69
fi
if [[ $# -ne 3 ]]; then
    printf 'usage: %s PACKAGE_DIR AGENT_USER RELEASE_ID\n' "$0" >&2
    exit 64
fi

readonly PACKAGE_DIR=$1
readonly AGENT_USER=$2
readonly RELEASE_ID=$3
readonly LABEL=com.plntir.endpoint-integrity
readonly CHECKER_SOURCE=${PACKAGE_DIR}/mac/libexec/plntir-integrity-check
readonly PLIST_SOURCE=${PACKAGE_DIR}/mac/launchd/com.plntir.endpoint-integrity.plist
readonly CHECKER_TARGET=/usr/local/libexec/plntir-integrity-check
readonly PLIST_TARGET=/Library/LaunchDaemons/com.plntir.endpoint-integrity.plist
readonly PLNTIR_ROOT='/Library/Application Support/Plntir'
readonly STATE_DIR=${PLNTIR_ROOT}/Integrity
readonly RECOVERY_ROOT=${PLNTIR_ROOT}/Recovery
readonly BASELINE=${STATE_DIR}/baseline.tsv
readonly RELEASE_FILE=${STATE_DIR}/release-id
readonly STATUS_FILE=${STATE_DIR}/status.env

ensure_protected_directory() {
    local path=$1
    local metadata
    if [[ -L ${path} || (-e ${path} && ! -d ${path}) ]]; then
        printf 'Unsafe integrity-monitor directory: %s\n' "${path}" >&2
        return 1
    fi
    if [[ ! -d ${path} ]]; then
        /usr/bin/install -d -o root -g wheel -m 0755 "${path}"
    fi
    metadata=$(/usr/bin/stat -f '%Su:%Sg:%Lp' "${path}")
    [[ ${metadata} == root:wheel:755 ]] || {
        printf 'Unsafe integrity-monitor directory metadata: %s (%s)\n' \
            "${path}" "${metadata}" >&2
        return 1
    }
}

[[ ${AGENT_USER} =~ ^[A-Za-z0-9._-]+$ && ! ${AGENT_USER} == -* ]] || exit 64
[[ ${RELEASE_ID} =~ ^[A-Za-z0-9._-]{8,128}$ ]] || exit 64
for source in "${CHECKER_SOURCE}" "${PLIST_SOURCE}"; do
    [[ -f ${source} && ! -L ${source} ]] || {
        printf 'Missing or unsafe integrity payload: %s\n' "${source}" >&2
        exit 66
    }
done
/usr/bin/plutil -lint "${PLIST_SOURCE}" >/dev/null

agent_home=$(/usr/bin/dscl . -read "/Users/${AGENT_USER}" NFSHomeDirectory |
    /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
[[ ${agent_home} == /Users/* && ${agent_home} != *[[:space:]]* ]] || exit 77
readonly agent_home

for directory in "${PLNTIR_ROOT}" "${STATE_DIR}" "${RECOVERY_ROOT}"; do
    if [[ -L ${directory} || (-e ${directory} && ! -d ${directory}) ]]; then
        printf 'Unsafe Plntir integrity directory: %s\n' "${directory}" >&2
        exit 77
    fi
done
/usr/bin/install -d -o root -g wheel -m 0755 "${PLNTIR_ROOT}" "${STATE_DIR}"
/usr/bin/install -d -o root -g wheel -m 0700 "${RECOVERY_ROOT}"

stamp=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly stamp
backup_dir=/var/backups/plntir/${stamp}-integrity-monitor
readonly backup_dir
/usr/bin/install -d -o root -g wheel -m 0700 "${backup_dir}"
for target in "${CHECKER_TARGET}" "${PLIST_TARGET}" "${BASELINE}" "${RELEASE_FILE}" "${STATUS_FILE}"; do
    if [[ -e ${target} ]]; then
        /bin/cp -a "${target}" "${backup_dir}/$(/usr/bin/basename "${target}").before"
    fi
done

ensure_protected_directory /usr/local
ensure_protected_directory /usr/local/libexec
ensure_protected_directory /Library/LaunchDaemons
/usr/bin/install -o root -g wheel -m 0755 "${CHECKER_SOURCE}" "${CHECKER_TARGET}"
/usr/bin/install -o root -g wheel -m 0644 "${PLIST_SOURCE}" "${PLIST_TARGET}"
/usr/bin/plutil -lint "${PLIST_TARGET}" >/dev/null

protected_paths=(
    /usr/local/libexec/plntir-health-collector
    /usr/local/libexec/plntir-monitor-dispatch
    /usr/local/libexec/plntir-response-dispatch
    /usr/local/libexec/plntir-response-status
    /usr/local/libexec/plntir-security-collector
    /usr/local/libexec/plntir-retrieval-export
    /usr/local/libexec/plntir-retrieval-export.py
    /usr/local/libexec/plntir-secure-archive
    /usr/local/libexec/plntir-secure-archive-dispatch
    "${CHECKER_TARGET}"
    /etc/ssh/sshd_config.d/90-plntir.conf
    /etc/sudoers.d/90-plntir
    /etc/sudoers.d/91-plntir-secure-archive
    "${agent_home}/.ssh/authorized_keys"
    "${PLIST_TARGET}"
)

version_dir=${RECOVERY_ROOT}/${RELEASE_ID}-${stamp}
readonly version_dir
/usr/bin/install -d -o root -g wheel -m 0700 "${version_dir}/files"
manifest_tmp=${STATE_DIR}/.baseline.$$
release_tmp=${STATE_DIR}/.release.$$
trap '/bin/rm -f "${manifest_tmp}" "${release_tmp}"' EXIT
: >"${manifest_tmp}"
index=0
for target in "${protected_paths[@]}"; do
    [[ -f ${target} && ! -L ${target} ]] || {
        printf 'Protected Plntir file is missing or unsafe: %s\n' "${target}" >&2
        exit 66
    }
    index=$((index + 1))
    recovery_name=$(/usr/bin/printf 'files/%04d' "${index}")
    hash=$(/usr/bin/shasum -a 256 "${target}" | /usr/bin/awk '{print $1}')
    metadata=$(/usr/bin/stat -f '%Lp	%Su	%Sg' "${target}")
    IFS=$'\t' read -r mode owner group <<<"${metadata}"
    /usr/bin/printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${hash}" "${mode}" "${owner}" "${group}" "${target}" "${recovery_name}" \
        >>"${manifest_tmp}"
    /usr/bin/install -o root -g wheel -m 0600 "${target}" "${version_dir}/${recovery_name}"
done
/bin/chmod 0600 "${manifest_tmp}"
/usr/bin/printf '%s\n' "${RELEASE_ID}" >"${release_tmp}"
/bin/chmod 0644 "${release_tmp}"
/bin/mv -f "${manifest_tmp}" "${BASELINE}"
/bin/mv -f "${release_tmp}" "${RELEASE_FILE}"
trap - EXIT
/usr/sbin/chown root:wheel "${BASELINE}" "${RELEASE_FILE}"
/bin/chmod 0600 "${BASELINE}"
/bin/chmod 0644 "${RELEASE_FILE}"

"${CHECKER_TARGET}" --check
/usr/bin/grep -Fxq 'integrity_state=healthy' "${STATUS_FILE}"

/bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
/bin/launchctl bootstrap system "${PLIST_TARGET}"
/bin/launchctl kickstart -k "system/${LABEL}"
/bin/launchctl print "system/${LABEL}" >/dev/null

printf 'Plntir endpoint integrity monitor installed in alert-only mode.\n'
printf 'Release: %s\n' "${RELEASE_ID}"
printf 'Rollback evidence: %s\n' "${backup_dir}"
