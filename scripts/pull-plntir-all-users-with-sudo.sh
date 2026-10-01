#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 || ($1 != --check && $1 != --pull) ]]; then
    printf 'usage: %s --check|--pull OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly MODE=$1
readonly OUTPUT_DIR=$2
readonly PLNTIR_CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly PLNTIR_CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}
readonly ARCHIVE_TARGET=${ARCHIVE_TARGET:-macagent@100.101.0.2}
readonly RECOVERY_TARGET=${RECOVERY_TARGET:-bootstrapadmin@100.101.0.2}
readonly PLNTIR_CONTROL_NODE_KEY=${ROOT}/secrets/plntir_control_node_access.pem
readonly PLNTIR_CONTROL_NODE_HOST_KEYS=${ROOT}/secrets/plntir_control_node_known_hosts
readonly ARCHIVE_KEY=${ROOT}/secrets/plntir_endpoint_archive_ed25519
readonly RECOVERY_KEY=${ROOT}/secrets/plntir_recovery_ed25519
readonly MAC_HOST_KEYS=${ROOT}/secrets/plntir_endpoint_known_hosts
readonly RECIPIENT_FILE=${ROOT}/secrets/plntir_secure_archive_public.asc
readonly MIN_RESERVE_BYTES=$((10 * 1024 * 1024 * 1024))

for value in "${ARCHIVE_TARGET}" "${RECOVERY_TARGET}"; do
    [[ ${value} =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.:-]+$ ]] || exit 64
done
[[ ${PLNTIR_CONTROL_NODE_HOST} =~ ^[A-Za-z0-9.:-]+$ ]] || exit 64
[[ ${PLNTIR_CONTROL_NODE_USER} =~ ^[A-Za-z0-9._-]+$ ]] || exit 64
for path in "${PLNTIR_CONTROL_NODE_KEY}" "${PLNTIR_CONTROL_NODE_HOST_KEYS}" \
    "${ARCHIVE_KEY}" "${RECOVERY_KEY}" "${MAC_HOST_KEYS}" "${RECIPIENT_FILE}"; do
    [[ -f ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe Plntir credential file: %s\n' "${path}" >&2
        exit 66
    }
done
for command in /usr/bin/ssh /usr/bin/jq /usr/bin/gpg /usr/bin/zstd \
    /usr/bin/sha256sum /bin/df; do
    [[ -x ${command} ]] || {
        printf 'Required command is unavailable: %s\n' "${command}" >&2
        exit 69
    }
done

[[ ! -L ${OUTPUT_DIR} ]] || {
    printf 'Output directory must not be a symlink.\n' >&2
    exit 77
}
/usr/bin/install -d -m 0700 "${OUTPUT_DIR}"
[[ -d ${OUTPUT_DIR} && -w ${OUTPUT_DIR} ]] || exit 77

printf -v proxy_command \
    '/usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -i %q -W %%h:%%p %q@%q' \
    "${PLNTIR_CONTROL_NODE_HOST_KEYS}" "${PLNTIR_CONTROL_NODE_KEY}" \
    "${PLNTIR_CONTROL_NODE_USER}" "${PLNTIR_CONTROL_NODE_HOST}"

common_ssh_options=(
    -T
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o IdentitiesOnly=yes
    -o PasswordAuthentication=no
    -o PermitLocalCommand=no
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=4
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${MAC_HOST_KEYS}"
    -o ProxyCommand="${proxy_command}"
)
archive_ssh=(
    /usr/bin/ssh
    "${common_ssh_options[@]}"
    -i "${ARCHIVE_KEY}"
    "${ARCHIVE_TARGET}"
)
recovery_ssh=(
    /usr/bin/ssh
    "${common_ssh_options[@]}"
    -i "${RECOVERY_KEY}"
    "${RECOVERY_TARGET}"
)

plan=$("${archive_ssh[@]}" all-users-plan-v1)
/usr/bin/jq -e \
    '.schema_version == 1 and .scope == "all-users" and (.ok | type == "boolean") and (.bytes | type == "number") and (.unreadable_entries | type == "number")' \
    <<<"${plan}" >/dev/null || {
    printf 'The Mac returned an invalid all-user plan.\n' >&2
    exit 65
}
if [[ $(/usr/bin/jq -r '.ok' <<<"${plan}") != true ]]; then
    /usr/bin/jq . <<<"${plan}" >&2
    printf 'The Mac refused a complete archive because some data is not readable.\n' >&2
    exit 77
fi

source_bytes=$(/usr/bin/jq -r '.bytes' <<<"${plan}")
unreadable_entries=$(/usr/bin/jq -r '.unreadable_entries' <<<"${plan}")
local_user_count=$(/usr/bin/jq -r '.local_user_count' <<<"${plan}")
home_directory_count=$(/usr/bin/jq -r '.home_directory_count' <<<"${plan}")
for value in "${source_bytes}" "${unreadable_entries}" "${local_user_count}" \
    "${home_directory_count}"; do
    [[ ${value} =~ ^[0-9]+$ ]] || exit 65
done

read -r filesystem_kib available_kib < <(/bin/df -Pk "${OUTPUT_DIR}" |
    /usr/bin/awk 'NR == 2 {print $2, $4}')
[[ ${filesystem_kib} =~ ^[0-9]+$ && ${available_kib} =~ ^[0-9]+$ ]] || exit 65
filesystem_bytes=$((filesystem_kib * 1024))
available_bytes=$((available_kib * 1024))
reserve_bytes=$((filesystem_bytes / 10))
if ((reserve_bytes < MIN_RESERVE_BYTES)); then
    reserve_bytes=${MIN_RESERVE_BYTES}
fi
required_bytes=$((source_bytes + source_bytes / 5 + reserve_bytes))

human_bytes() {
    /usr/bin/numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || printf '%d bytes' "$1"
}

printf 'Plntir all-user source: %s across %d users and %d home directories.\n' \
    "$(human_bytes "${source_bytes}")" "${local_user_count}" "${home_directory_count}"
printf 'Destination available: %s; conservative requirement: %s.\n' \
    "$(human_bytes "${available_bytes}")" "$(human_bytes "${required_bytes}")"
if ((available_bytes < required_bytes)); then
    missing_bytes=$((required_bytes - available_bytes))
    printf 'INSUFFICIENT STORAGE: add at least %s before starting the pull.\n' \
        "$(human_bytes "${missing_bytes}")" >&2
    exit 75
fi
if [[ ${MODE} == --check ]]; then
    printf 'Storage and Mac readability checks passed. No data was transferred.\n'
    exit 0
fi

gpg_home=$(/usr/bin/mktemp -d)
sudo_password=''
partial=''
manifest_partial=''
cleanup() {
    local rc=$?
    trap - EXIT HUP INT TERM
    unset sudo_password
    [[ -z ${partial} ]] || /bin/rm -f -- "${partial}"
    [[ -z ${manifest_partial} ]] || /bin/rm -f -- "${manifest_partial}"
    case ${gpg_home} in
    /tmp/* | /var/tmp/*) /bin/rm -rf -- "${gpg_home}" ;;
    *) printf 'Refusing unsafe GPG temporary cleanup path.\n' >&2 ;;
    esac
    exit "${rc}"
}
trap cleanup EXIT HUP INT TERM
/bin/chmod 0700 "${gpg_home}"
/usr/bin/gpg --homedir "${gpg_home}" --batch --quiet --import \
    "${RECIPIENT_FILE}" >/dev/null 2>&1
recipient=$(/usr/bin/gpg --homedir "${gpg_home}" --batch --with-colons \
    --fingerprint --list-keys | /usr/bin/awk -F: '$1 == "fpr" {print $10; exit}')
[[ ${recipient} =~ ^[A-Fa-f0-9]{40,64}$ ]] || {
    printf 'Could not determine the pinned archive recipient.\n' >&2
    exit 65
}

timestamp=$(/bin/date -u +%Y%m%dT%H%M%SZ)
archive=plntir-all-users-${timestamp}.tar.zst.gpg
readonly final=${OUTPUT_DIR}/${archive}
partial=${OUTPUT_DIR}/.${archive}.partial.$$
readonly manifest=${final}.json
manifest_partial=${OUTPUT_DIR}/.${archive}.manifest.partial.$$
for path in "${final}" "${partial}" "${manifest}" "${manifest_partial}"; do
    [[ ! -e ${path} && ! -L ${path} ]] || {
        printf 'Refusing an existing output path: %s\n' "${path}" >&2
        exit 73
    }
done

printf 'The password is used only for sudo on the Mac and is never written to disk or command history.\n'
IFS= read -r -s -p 'bootstrapadmin sudo password: ' sudo_password </dev/tty
printf '\n'
[[ -n ${sudo_password} && ${sudo_password} != *$'\n'* ]] || {
    printf 'A non-empty single-line sudo password is required.\n' >&2
    exit 77
}

set +e
{
    printf '%s\n' "${sudo_password}"
    unset sudo_password
} | "${recovery_ssh[@]}" \
    /usr/bin/sudo -S -k -p '' /usr/local/libexec/plntir-secure-archive stream-v1 |
    /usr/bin/zstd -q -T0 -3 |
    /usr/bin/gpg \
        --homedir "${gpg_home}" \
        --batch \
        --no-tty \
        --yes \
        --trust-model always \
        --compress-algo none \
        --recipient "${recipient}" \
        --output "${partial}" \
        --encrypt
pipeline_status=("${PIPESTATUS[@]}")
set -e
unset sudo_password
if [[ ${pipeline_status[0]} -ne 0 || ${pipeline_status[1]} -ne 0 ||
    ${pipeline_status[2]} -ne 0 || ${pipeline_status[3]} -ne 0 ]]; then
    printf 'Encrypted pull failed (%s/%s/%s/%s). No partial archive was retained.\n' \
        "${pipeline_status[0]}" "${pipeline_status[1]}" \
        "${pipeline_status[2]}" "${pipeline_status[3]}" >&2
    exit 74
fi

/bin/chmod 0600 "${partial}"
archive_bytes=$(/usr/bin/stat -Lc %s "${partial}")
archive_sha256=$(/usr/bin/sha256sum "${partial}" | /usr/bin/awk '{print $1}')
completed_at=$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
/usr/bin/jq -cn \
    --arg archive "${archive}" \
    --arg completed_at "${completed_at}" \
    --arg sha256 "${archive_sha256}" \
    --arg authorization bootstrapadmin-sudo-password \
    --argjson archive_bytes "${archive_bytes}" \
    --argjson source_bytes "${source_bytes}" \
    --argjson local_user_count "${local_user_count}" \
    --argjson home_directory_count "${home_directory_count}" \
    '{schema_version:1,archive:$archive,completed_at:$completed_at,sha256:$sha256,archive_bytes:$archive_bytes,source_bytes:$source_bytes,local_user_count:$local_user_count,home_directory_count:$home_directory_count,encrypted:true,compression:"zstd",authorization:$authorization}' \
    >"${manifest_partial}"
/bin/chmod 0600 "${manifest_partial}"
/bin/mv -f "${partial}" "${final}"
partial=''
/bin/mv -f "${manifest_partial}" "${manifest}"
manifest_partial=''

"${ROOT}/scripts/decrypt-plntir-secure-archive.sh" --verify "${final}"
trap - EXIT HUP INT TERM
/bin/rm -rf -- "${gpg_home}"
printf 'Verified encrypted all-user archive: %s\n' "${final}"
printf 'SHA-256: %s\n' "${archive_sha256}"
