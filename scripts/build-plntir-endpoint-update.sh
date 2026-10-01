#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 6 ]]; then
    printf 'usage: %s OUTPUT_DIR MANAGED_USER LEGACY_SSH_USER PLNTIR_CONTROL_NODE_IP MONITOR_PUBLIC_KEY RESPONSE_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly OUTPUT_DIR=$1
readonly MANAGED_USER=$2
readonly LEGACY_SSH_USER=$3
readonly PLNTIR_CONTROL_NODE_IP=$4
readonly MONITOR_PUBLIC_KEY=$5
readonly RESPONSE_PUBLIC_KEY=$6
readonly AGENT_USER=macagent
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT

for account in "${MANAGED_USER}" "${LEGACY_SSH_USER}"; do
    [[ ${account} =~ ^[A-Za-z0-9._-]+$ && ! ${account} == -* ]] || {
        printf 'Invalid account name: %s\n' "${account}" >&2
        exit 64
    }
done
[[ ${PLNTIR_CONTROL_NODE_IP} =~ ^[A-Fa-f0-9:./]+$ ]] || {
    printf 'Invalid Plntir Control Node address.\n' >&2
    exit 64
}

validate_public_key() {
    local path=$1
    local type
    [[ -f ${path} && ! -L ${path} ]] || return 1
    ssh-keygen -l -f "${path}" >/dev/null
    [[ $(awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' "${path}") -eq 1 ]]
    type=$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "${path}")
    [[ ${type} == ssh-ed25519 || ${type} == sk-ssh-ed25519@openssh.com ]]
}
validate_public_key "${MONITOR_PUBLIC_KEY}" || {
    printf 'Invalid monitor public key.\n' >&2
    exit 65
}
validate_public_key "${RESPONSE_PUBLIC_KEY}" || {
    printf 'Invalid response public key.\n' >&2
    exit 65
}
monitor_blob=$(awk 'NF && $1 !~ /^#/ {print $2; exit}' "${MONITOR_PUBLIC_KEY}")
response_blob=$(awk 'NF && $1 !~ /^#/ {print $2; exit}' "${RESPONSE_PUBLIC_KEY}")
[[ ${monitor_blob} != "${response_blob}" ]] || {
    printf 'Monitor and response keys must be distinct.\n' >&2
    exit 65
}

install -d -m 0700 "${OUTPUT_DIR}"
workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT
readonly PACKAGE_DIR=${workdir}/plntir-endpoint-update
install -d -m 0755 \
    "${PACKAGE_DIR}/keys" \
    "${PACKAGE_DIR}/mac/libexec" \
    "${PACKAGE_DIR}/mac/sshd" \
    "${PACKAGE_DIR}/mac/sudoers" \
    "${PACKAGE_DIR}/scripts"

install -m 0755 "${ROOT}/scripts/install-plntir-endpoint-update.sh" "${PACKAGE_DIR}/install.sh"
install -m 0755 \
    "${ROOT}/scripts/provision-plntir-endpoint.sh" \
    "${ROOT}/scripts/verify-plntir-endpoint.sh" \
    "${PACKAGE_DIR}/scripts/"
install -m 0644 \
    "${ROOT}/scripts/plntir-dscl-output.sh" \
    "${PACKAGE_DIR}/scripts/"
install -m 0755 \
    "${ROOT}/mac/libexec/plntir-health-collector" \
    "${ROOT}/mac/libexec/plntir-monitor-dispatch" \
    "${ROOT}/mac/libexec/plntir-response-dispatch.in" \
    "${ROOT}/mac/libexec/plntir-response-status" \
    "${ROOT}/mac/libexec/plntir-security-collector" \
    "${ROOT}/mac/libexec/plntir-retrieval-export" \
    "${ROOT}/mac/libexec/plntir-retrieval-export.py.in" \
    "${PACKAGE_DIR}/mac/libexec/"
install -m 0644 "${ROOT}/mac/sshd/90-plntir-endpoint.conf.in" "${PACKAGE_DIR}/mac/sshd/"
install -m 0644 "${ROOT}/mac/sudoers/90-plntir-endpoint.in" "${PACKAGE_DIR}/mac/sudoers/"
install -m 0644 "${MONITOR_PUBLIC_KEY}" "${PACKAGE_DIR}/keys/monitor.pub"
install -m 0644 "${RESPONSE_PUBLIC_KEY}" "${PACKAGE_DIR}/keys/response.pub"

{
    printf 'AGENT_USER=%q\n' "${AGENT_USER}"
    printf 'MANAGED_USER=%q\n' "${MANAGED_USER}"
    printf 'LEGACY_SSH_USER=%q\n' "${LEGACY_SSH_USER}"
    printf 'PLNTIR_CONTROL_NODE_IP=%q\n' "${PLNTIR_CONTROL_NODE_IP}"
} >"${PACKAGE_DIR}/deployment.conf"
chmod 0644 "${PACKAGE_DIR}/deployment.conf"

archive_tmp=$(mktemp "${OUTPUT_DIR}/.plntir-endpoint-update.XXXXXX")
tar -czf "${archive_tmp}" -C "${workdir}" plntir-endpoint-update
archive=${OUTPUT_DIR}/plntir-endpoint-update.tar.gz
mv -f "${archive_tmp}" "${archive}"
chmod 0644 "${archive}"
for required in \
    plntir-endpoint-update/install.sh \
    plntir-endpoint-update/deployment.conf \
    plntir-endpoint-update/keys/monitor.pub \
    plntir-endpoint-update/keys/response.pub; do
    tar -tzf "${archive}" | grep -Fxq "${required}" || {
        printf 'Built archive is missing: %s\n' "${required}" >&2
        exit 66
    }
done
checksum=$(sha256sum "${archive}" | awk '{print $1}')
printf '%s  plntir-endpoint-update.tar.gz\n' "${checksum}" >"${OUTPUT_DIR}/plntir-endpoint-update.sha256"
runner_tmp=$(mktemp "${OUTPUT_DIR}/.run.sh.XXXXXX")
/usr/bin/sed \
    -e "s/@CHECKSUM@/${checksum}/g" \
    -e "s/@OWNER@/${LEGACY_SSH_USER}/g" \
    "${ROOT}/scripts/run-plntir-endpoint-update.sh.in" >"${runner_tmp}"
chmod 0555 "${runner_tmp}"
mv -f "${runner_tmp}" "${OUTPUT_DIR}/run.sh"
printf '%s\n' 'sudo /Users/Shared/.plntir/inbox/endpoint-update/run.sh' >"${OUTPUT_DIR}/RUN_ME.txt"
chmod 0644 "${OUTPUT_DIR}/plntir-endpoint-update.sha256" "${OUTPUT_DIR}/RUN_ME.txt"

printf 'Archive: %s\n' "${archive}"
printf 'SHA-256: %s\n' "${checksum}"
printf 'Command: %s\n' "${OUTPUT_DIR}/RUN_ME.txt"
