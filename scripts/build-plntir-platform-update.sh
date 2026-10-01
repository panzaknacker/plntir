#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 9 ]]; then
    printf 'usage: %s OUTPUT_DIR MANAGED_USER RECOVERY_USER CONTROL_NODE_IP MONITOR_PUBLIC_KEY RESPONSE_PUBLIC_KEY ARCHIVE_PUBLIC_KEY RECOVERY_PUBLIC_KEY RELEASE_SIGNING_KEY\n' "$0" >&2
    exit 64
fi

readonly OUTPUT_DIR=$1
readonly MANAGED_USER=$2
readonly RECOVERY_USER=$3
readonly CONTROL_NODE_IP=$4
readonly MONITOR_PUBLIC_KEY=$5
readonly RESPONSE_PUBLIC_KEY=$6
readonly ARCHIVE_PUBLIC_KEY=$7
readonly RECOVERY_PUBLIC_KEY=$8
readonly RELEASE_SIGNING_KEY=$9
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT

for account in "${MANAGED_USER}" "${RECOVERY_USER}"; do
    [[ ${account} =~ ^[A-Za-z0-9._-]+$ && ! ${account} == -* ]] || {
        printf 'Invalid account name: %s\n' "${account}" >&2
        exit 64
    }
done
[[ ${CONTROL_NODE_IP} =~ ^[A-Fa-f0-9:.]+$ ]] || {
    printf 'Invalid Plntir Control Node address.\n' >&2
    exit 64
}
[[ -f ${RELEASE_SIGNING_KEY} && ! -L ${RELEASE_SIGNING_KEY} ]] || {
    printf 'Release signing key is missing or unsafe.\n' >&2
    exit 66
}
[[ $(/usr/bin/stat -c %a "${RELEASE_SIGNING_KEY}") =~ ^[46]00$ ]] || {
    printf 'Release signing key must use mode 0400 or 0600.\n' >&2
    exit 77
}
signer_output=$(/usr/bin/ssh-keygen -y -P '' -f "${RELEASE_SIGNING_KEY}") || {
    printf 'Release signing key must be an unencrypted Ed25519 key.\n' >&2
    exit 65
}
signer_type=$(/usr/bin/awk '{print $1}' <<<"${signer_output}")
signer_blob=$(/usr/bin/awk '{print $2}' <<<"${signer_output}")
[[ ${signer_type} == ssh-ed25519 && ${signer_blob} =~ ^[A-Za-z0-9+/=]+$ ]] || {
    printf 'Release signing key must be Ed25519.\n' >&2
    exit 65
}
signer_public="${signer_type} ${signer_blob}"
readonly signer_public signer_type signer_blob

/usr/bin/install -d -m 0700 "${OUTPUT_DIR}"
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT

"${ROOT}/scripts/build-plntir-endpoint-update.sh" \
    "${workdir}/endpoint-output" \
    "${MANAGED_USER}" \
    "${RECOVERY_USER}" \
    "${CONTROL_NODE_IP}" \
    "${MONITOR_PUBLIC_KEY}" \
    "${RESPONSE_PUBLIC_KEY}"
"${ROOT}/scripts/build-plntir-access-upgrade.sh" \
    "${workdir}/access-output" \
    macagent \
    "${RECOVERY_USER}" \
    "${CONTROL_NODE_IP}" \
    "${ARCHIVE_PUBLIC_KEY}" \
    "${RECOVERY_PUBLIC_KEY}"

endpoint_archive=${workdir}/endpoint-output/plntir-endpoint-update.tar.gz
access_archive=${workdir}/access-output/plntir-access-upgrade.tar.gz
endpoint_checksum=$(/usr/bin/sha256sum "${endpoint_archive}" | /usr/bin/awk '{print $1}')
access_checksum=$(/usr/bin/sha256sum "${access_archive}" | /usr/bin/awk '{print $1}')
readonly endpoint_archive access_archive endpoint_checksum access_checksum

readonly PACKAGE_DIR=${workdir}/plntir-platform-update
/usr/bin/install -d -m 0755 \
    "${PACKAGE_DIR}/payloads" \
    "${PACKAGE_DIR}/mac/libexec" \
    "${PACKAGE_DIR}/mac/launchd" \
    "${PACKAGE_DIR}/scripts"
/usr/bin/install -m 0644 "${endpoint_archive}" \
    "${PACKAGE_DIR}/payloads/plntir-endpoint-update.tar.gz"
/usr/bin/install -m 0644 "${access_archive}" \
    "${PACKAGE_DIR}/payloads/plntir-access-upgrade.tar.gz"
release_id=ep-${endpoint_checksum:0:12}-ac-${access_checksum:0:12}
readonly release_id
/usr/bin/install -m 0755 \
    "${ROOT}/mac/libexec/plntir-integrity-check" \
    "${PACKAGE_DIR}/mac/libexec/"
/usr/bin/install -m 0644 \
    "${ROOT}/mac/launchd/com.plntir.endpoint-integrity.plist" \
    "${PACKAGE_DIR}/mac/launchd/"
/usr/bin/install -m 0755 \
    "${ROOT}/scripts/install-plntir-integrity-monitor.sh" \
    "${PACKAGE_DIR}/scripts/"
/usr/bin/sed \
    -e "s/@ENDPOINT_CHECKSUM@/${endpoint_checksum}/g" \
    -e "s/@ACCESS_CHECKSUM@/${access_checksum}/g" \
    -e "s/@RELEASE_ID@/${release_id}/g" \
    "${ROOT}/scripts/install-plntir-platform-update.sh.in" \
    >"${PACKAGE_DIR}/install.sh"
/bin/chmod 0755 "${PACKAGE_DIR}/install.sh"

archive_tmp=${workdir}/plntir-platform-update.tar.gz
/usr/bin/tar -czf "${archive_tmp}" -C "${workdir}" plntir-platform-update
signature_tmp=${archive_tmp}.sig
/usr/bin/ssh-keygen -Y sign \
    -f "${RELEASE_SIGNING_KEY}" \
    -n plntir-endpoint-recovery \
    "${archive_tmp}" >/dev/null
[[ -s ${signature_tmp} ]] || {
    printf 'Release signature was not created.\n' >&2
    exit 74
}
allowed_signers_tmp=${workdir}/plntir-release-allowed-signers
/usr/bin/printf 'plntir-release namespaces="plntir-endpoint-recovery" %s\n' \
    "${signer_public}" >"${allowed_signers_tmp}"
/usr/bin/ssh-keygen -Y verify \
    -f "${allowed_signers_tmp}" \
    -I plntir-release \
    -n plntir-endpoint-recovery \
    -s "${signature_tmp}" <"${archive_tmp}" >/dev/null
archive=${OUTPUT_DIR}/plntir-platform-update.tar.gz
/usr/bin/install -m 0644 "${archive_tmp}" "${archive}"
/usr/bin/install -m 0644 "${signature_tmp}" \
    "${OUTPUT_DIR}/plntir-platform-update.tar.gz.sig"
/usr/bin/install -m 0644 "${allowed_signers_tmp}" \
    "${OUTPUT_DIR}/plntir-release-allowed-signers"
for required in \
    plntir-platform-update/install.sh \
    plntir-platform-update/payloads/plntir-endpoint-update.tar.gz \
    plntir-platform-update/payloads/plntir-access-upgrade.tar.gz \
    plntir-platform-update/mac/libexec/plntir-integrity-check \
    plntir-platform-update/mac/launchd/com.plntir.endpoint-integrity.plist \
    plntir-platform-update/scripts/install-plntir-integrity-monitor.sh; do
    /usr/bin/tar -tzf "${archive}" | /usr/bin/grep -Fxq "${required}" || {
        printf 'Built archive is missing: %s\n' "${required}" >&2
        exit 66
    }
done

checksum=$(/usr/bin/sha256sum "${archive}" | /usr/bin/awk '{print $1}')
printf '%s  plntir-platform-update.tar.gz\n' "${checksum}" \
    >"${OUTPUT_DIR}/plntir-platform-update.sha256"
runner_tmp=$(/usr/bin/mktemp "${OUTPUT_DIR}/.run.sh.XXXXXX")
/usr/bin/sed \
    -e "s/@CHECKSUM@/${checksum}/g" \
    -e "s/@OWNER@/${RECOVERY_USER}/g" \
    -e "s|@SIGNER_TYPE@|${signer_type}|g" \
    -e "s|@SIGNER_BLOB@|${signer_blob}|g" \
    "${ROOT}/scripts/run-plntir-platform-update.sh.in" >"${runner_tmp}"
/bin/chmod 0555 "${runner_tmp}"
/bin/mv -f "${runner_tmp}" "${OUTPUT_DIR}/run.sh"
printf '%s\n' 'sudo /Users/Shared/.plntir/inbox/platform-update/run.sh' \
    >"${OUTPUT_DIR}/RUN_ME.txt"
/bin/chmod 0644 \
    "${OUTPUT_DIR}/plntir-platform-update.sha256" \
    "${OUTPUT_DIR}/plntir-platform-update.tar.gz.sig" \
    "${OUTPUT_DIR}/plntir-release-allowed-signers" \
    "${OUTPUT_DIR}/RUN_ME.txt"

printf 'Archive: %s\n' "${archive}"
printf 'SHA-256: %s\n' "${checksum}"
printf 'Signature namespace: plntir-endpoint-recovery\n'
printf 'Command: %s\n' "${OUTPUT_DIR}/RUN_ME.txt"
