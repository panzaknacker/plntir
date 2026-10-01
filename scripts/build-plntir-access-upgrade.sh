#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 6 ]]; then
    printf 'usage: %s OUTPUT_DIR AGENT_USER BREAKGLASS_USER PLNTIR_CONTROL_NODE_IP ARCHIVE_PUBLIC_KEY BREAKGLASS_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly OUTPUT_DIR=$1
readonly AGENT_USER=$2
readonly BREAKGLASS_USER=$3
readonly PLNTIR_CONTROL_NODE_IP=$4
readonly ARCHIVE_PUBLIC_KEY=$5
readonly BREAKGLASS_PUBLIC_KEY=$6
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT

for account in "${AGENT_USER}" "${BREAKGLASS_USER}"; do
    [[ ${account} =~ ^[A-Za-z0-9._-]+$ && ! ${account} == -* ]] || {
        printf 'Invalid account name: %s\n' "${account}" >&2
        exit 64
    }
done
[[ ${AGENT_USER} != "${BREAKGLASS_USER}" ]] || exit 64
[[ ${PLNTIR_CONTROL_NODE_IP} =~ ^[A-Fa-f0-9:.]+$ ]] || exit 64

validate_public_key() {
    local path=$1
    local type
    [[ -f ${path} && ! -L ${path} ]] || return 1
    /usr/bin/ssh-keygen -l -f "${path}" >/dev/null
    [[ $(/usr/bin/awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' "${path}") -eq 1 ]]
    type=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $1; exit}' "${path}")
    [[ ${type} == ssh-ed25519 ]]
}
validate_public_key "${ARCHIVE_PUBLIC_KEY}" || exit 65
validate_public_key "${BREAKGLASS_PUBLIC_KEY}" || exit 65
archive_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${ARCHIVE_PUBLIC_KEY}")
breakglass_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${BREAKGLASS_PUBLIC_KEY}")
[[ ${archive_blob} != "${breakglass_blob}" ]] || exit 65

/usr/bin/install -d -m 0700 "${OUTPUT_DIR}"
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT
readonly PACKAGE_DIR=${workdir}/plntir-access-upgrade
/usr/bin/install -d -m 0755 \
    "${PACKAGE_DIR}/keys" \
    "${PACKAGE_DIR}/mac/libexec" \
    "${PACKAGE_DIR}/mac/sudoers" \
    "${PACKAGE_DIR}/scripts"

/usr/bin/install -m 0755 "${ROOT}/scripts/install-plntir-access-upgrade.sh" "${PACKAGE_DIR}/install.sh"
/usr/bin/install -m 0755 \
    "${ROOT}/scripts/provision-plntir-access-upgrade.sh" \
    "${ROOT}/scripts/verify-plntir-access-upgrade.sh" \
    "${PACKAGE_DIR}/scripts/"
/usr/bin/install -m 0644 \
    "${ROOT}/scripts/plntir-dscl-output.sh" \
    "${PACKAGE_DIR}/scripts/"
/usr/bin/install -m 0755 \
    "${ROOT}/mac/libexec/plntir-secure-archive" \
    "${ROOT}/mac/libexec/plntir-secure-archive-dispatch" \
    "${PACKAGE_DIR}/mac/libexec/"
/usr/bin/install -m 0644 \
    "${ROOT}/mac/sudoers/91-plntir-secure-archive.in" \
    "${PACKAGE_DIR}/mac/sudoers/"
/usr/bin/install -m 0644 "${ARCHIVE_PUBLIC_KEY}" "${PACKAGE_DIR}/keys/archive.pub"
/usr/bin/install -m 0644 "${BREAKGLASS_PUBLIC_KEY}" "${PACKAGE_DIR}/keys/breakglass.pub"

{
    printf 'AGENT_USER=%q\n' "${AGENT_USER}"
    printf 'BREAKGLASS_USER=%q\n' "${BREAKGLASS_USER}"
    printf 'PLNTIR_CONTROL_NODE_IP=%q\n' "${PLNTIR_CONTROL_NODE_IP}"
} >"${PACKAGE_DIR}/deployment.conf"
/bin/chmod 0644 "${PACKAGE_DIR}/deployment.conf"

archive_tmp=$(/usr/bin/mktemp "${OUTPUT_DIR}/.plntir-access-upgrade.XXXXXX")
/usr/bin/tar -czf "${archive_tmp}" -C "${workdir}" plntir-access-upgrade
archive=${OUTPUT_DIR}/plntir-access-upgrade.tar.gz
/bin/mv -f "${archive_tmp}" "${archive}"
/bin/chmod 0644 "${archive}"
for required in \
    plntir-access-upgrade/install.sh \
    plntir-access-upgrade/deployment.conf \
    plntir-access-upgrade/keys/archive.pub \
    plntir-access-upgrade/keys/breakglass.pub; do
    /usr/bin/tar -tzf "${archive}" | /usr/bin/grep -Fxq "${required}" || {
        printf 'Built archive is missing: %s\n' "${required}" >&2
        exit 66
    }
done
checksum=$(/usr/bin/sha256sum "${archive}" | /usr/bin/awk '{print $1}')
printf '%s  plntir-access-upgrade.tar.gz\n' "${checksum}" \
    >"${OUTPUT_DIR}/plntir-access-upgrade.sha256"
runner_tmp=$(/usr/bin/mktemp "${OUTPUT_DIR}/.run.sh.XXXXXX")
/usr/bin/sed \
    -e "s/@CHECKSUM@/${checksum}/g" \
    -e "s/@OWNER@/${BREAKGLASS_USER}/g" \
    "${ROOT}/scripts/run-plntir-access-upgrade.sh.in" >"${runner_tmp}"
/bin/chmod 0555 "${runner_tmp}"
/bin/mv -f "${runner_tmp}" "${OUTPUT_DIR}/run.sh"
printf '%s\n' 'sudo /Users/Shared/.plntir/inbox/access-upgrade/run.sh' \
    >"${OUTPUT_DIR}/RUN_ME.txt"
/bin/chmod 0644 \
    "${OUTPUT_DIR}/plntir-access-upgrade.sha256" \
    "${OUTPUT_DIR}/RUN_ME.txt"

printf 'Archive: %s\n' "${archive}"
printf 'SHA-256: %s\n' "${checksum}"
printf 'Command: %s\n' "${OUTPUT_DIR}/RUN_ME.txt"
