#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
fi
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly OUTPUT_DIR=$1
readonly PLNTIR_CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly PLNTIR_CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}
readonly PLNTIR_CONTROL_NODE_KEY=${ROOT}/secrets/plntir_control_node_access.pem
readonly PLNTIR_CONTROL_NODE_HOST_KEYS=${ROOT}/secrets/plntir_control_node_known_hosts

[[ ! -L ${OUTPUT_DIR} ]] || exit 77
/usr/bin/install -d -m 0700 "${OUTPUT_DIR}"
status=$("${ROOT}/scripts/plntir-secure-archive-status.sh")
archive=$(printf '%s\n' "${status}" | /usr/bin/jq -r '.archive // ""')
archive_bytes=$(printf '%s\n' "${status}" | /usr/bin/jq -r '.archive_bytes // 0')
expected_sha256=$(printf '%s\n' "${status}" | /usr/bin/jq -r '.sha256 // ""')
[[ ${archive} =~ ^all-users-[0-9]{8}T[0-9]{6}Z-[0-9]+[.]tar[.]zst[.]gpg$ ]] || {
    printf 'No completed encrypted all-user archive is recorded.\n' >&2
    exit 66
}
[[ ${archive_bytes} =~ ^[0-9]+$ && ${expected_sha256} =~ ^[A-Fa-f0-9]{64}$ ]] || exit 65
read -r available_kib < <(/bin/df -Pk "${OUTPUT_DIR}" | /usr/bin/awk 'NR == 2 {print $4}')
[[ ${available_kib} =~ ^[0-9]+$ ]] || exit 65
available_bytes=$((available_kib * 1024))
required_local=$((archive_bytes + 1024 * 1024 * 1024))
if ((available_bytes < required_local)); then
    printf 'Local storage is insufficient: need %d bytes including reserve, have %d.\n' \
        "${required_local}" "${available_bytes}" >&2
    exit 75
fi

readonly final=${OUTPUT_DIR}/${archive}
readonly partial=${OUTPUT_DIR}/.${archive}.partial.$$
readonly manifest=${OUTPUT_DIR}/${archive}.json
[[ ! -e ${final} && ! -L ${final} && ! -e ${partial} && ! -L ${partial} ]] || exit 73
cleanup() {
    local rc=$?
    trap - EXIT
    /bin/rm -f "${partial}"
    exit "${rc}"
}
trap cleanup EXIT

/usr/bin/scp \
    -P 22 \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${PLNTIR_CONTROL_NODE_HOST_KEYS}" \
    -i "${PLNTIR_CONTROL_NODE_KEY}" \
    "${PLNTIR_CONTROL_NODE_USER}@${PLNTIR_CONTROL_NODE_HOST}:/var/lib/plntir/retrieved/${archive}" \
    "${partial}"
actual_sha256=$(/usr/bin/sha256sum "${partial}" | /usr/bin/awk '{print $1}')
[[ ${actual_sha256} == "${expected_sha256}" ]] || {
    printf 'Downloaded archive checksum mismatch.\n' >&2
    exit 65
}
/bin/chmod 0600 "${partial}"
/bin/mv -f "${partial}" "${final}"
trap - EXIT

/usr/bin/scp \
    -P 22 \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${PLNTIR_CONTROL_NODE_HOST_KEYS}" \
    -i "${PLNTIR_CONTROL_NODE_KEY}" \
    "${PLNTIR_CONTROL_NODE_USER}@${PLNTIR_CONTROL_NODE_HOST}:/var/lib/plntir/retrieved/${archive}.json" \
    "${manifest}"
/bin/chmod 0600 "${manifest}"
"${ROOT}/scripts/decrypt-plntir-secure-archive.sh" --verify "${final}"
printf 'Verified encrypted archive downloaded to %s\n' "${final}"
