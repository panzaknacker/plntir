#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 5 ]]; then
    printf 'usage: %s OUTPUT_DIR PACKAGE_OWNER SOURCE_CERT EXPECTED_SHA256 EXPECTED_COMMON_NAME\n' "$0" >&2
    exit 64
fi

readonly OUTPUT_DIR=$1
readonly PACKAGE_OWNER=$2
readonly SOURCE_CERT=$3
EXPECTED_SHA256=$4
readonly EXPECTED_COMMON_NAME=$5
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT

[[ ${PACKAGE_OWNER} =~ ^[A-Za-z0-9._-]+$ && ! ${PACKAGE_OWNER} == -* ]] || exit 64
case ${SOURCE_CERT} in
/Library/Application\ Support/Cloudflare/installed_certs/*.pem) ;;
*)
    printf 'Certificate must be a Cloudflare One Client installed certificate.\n' >&2
    exit 64
    ;;
esac
cert_basename=${SOURCE_CERT##*/}
[[ ${cert_basename} =~ ^[0-9A-Fa-f-]+\.pem$ ]] || exit 64
EXPECTED_SHA256=$(/usr/bin/printf '%s' "${EXPECTED_SHA256}" | /usr/bin/tr '[:lower:]' '[:upper:]' | /usr/bin/tr -d ':')
readonly EXPECTED_SHA256
[[ ${EXPECTED_SHA256} =~ ^[0-9A-F]{64}$ ]] || exit 64
[[ ${EXPECTED_COMMON_NAME} == 'Gateway CA - Cloudflare Managed G1 '* ]] || exit 64
common_name_id=${EXPECTED_COMMON_NAME##* }
[[ ${common_name_id} =~ ^[0-9A-Fa-f]{32}$ ]] || exit 64

/usr/bin/install -d -m 0700 "${OUTPUT_DIR}"
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT
readonly PACKAGE_DIR=${workdir}/plntir-cloudflare-ca-trust
/usr/bin/install -d -m 0755 "${PACKAGE_DIR}"
/usr/bin/install -m 0755 "${ROOT}/scripts/install-plntir-cloudflare-ca-trust.sh" "${PACKAGE_DIR}/install.sh"

{
    printf 'SOURCE_CERT=%q\n' "${SOURCE_CERT}"
    printf 'EXPECTED_SHA256=%q\n' "${EXPECTED_SHA256}"
    printf 'EXPECTED_COMMON_NAME=%q\n' "${EXPECTED_COMMON_NAME}"
} >"${PACKAGE_DIR}/deployment.conf"
/bin/chmod 0644 "${PACKAGE_DIR}/deployment.conf"

archive_tmp=$(/usr/bin/mktemp "${OUTPUT_DIR}/.plntir-cloudflare-ca-trust.XXXXXX")
/usr/bin/tar -czf "${archive_tmp}" -C "${workdir}" plntir-cloudflare-ca-trust
archive=${OUTPUT_DIR}/plntir-cloudflare-ca-trust.tar.gz
/bin/mv -f "${archive_tmp}" "${archive}"
/bin/chmod 0644 "${archive}"
archive_listing=$(/usr/bin/tar -tzf "${archive}")
for required in \
    plntir-cloudflare-ca-trust/install.sh \
    plntir-cloudflare-ca-trust/deployment.conf; do
    /usr/bin/grep -Fx "${required}" <<<"${archive_listing}" >/dev/null || {
        printf 'Built archive is missing: %s\n' "${required}" >&2
        exit 66
    }
done
checksum=$(/usr/bin/sha256sum "${archive}" | /usr/bin/awk '{print $1}')
printf '%s  plntir-cloudflare-ca-trust.tar.gz\n' "${checksum}" \
    >"${OUTPUT_DIR}/plntir-cloudflare-ca-trust.sha256"
runner_tmp=$(/usr/bin/mktemp "${OUTPUT_DIR}/.run.sh.XXXXXX")
/usr/bin/sed \
    -e "s/@CHECKSUM@/${checksum}/g" \
    -e "s/@OWNER@/${PACKAGE_OWNER}/g" \
    "${ROOT}/scripts/run-plntir-cloudflare-ca-trust.sh.in" >"${runner_tmp}"
/bin/chmod 0555 "${runner_tmp}"
/bin/mv -f "${runner_tmp}" "${OUTPUT_DIR}/run.sh"
printf '%s\n' 'sudo /Users/Shared/.plntir/inbox/cloudflare-ca-trust/run.sh' \
    >"${OUTPUT_DIR}/RUN_ME.txt"
/bin/chmod 0644 \
    "${OUTPUT_DIR}/plntir-cloudflare-ca-trust.sha256" \
    "${OUTPUT_DIR}/RUN_ME.txt"

printf 'Archive: %s\n' "${archive}"
printf 'SHA-256: %s\n' "${checksum}"
printf 'Command: %s\n' "${OUTPUT_DIR}/RUN_ME.txt"
