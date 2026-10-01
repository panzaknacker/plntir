#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT

source_root=${workdir}/source
state_dir=${workdir}/state
output_dir=${workdir}/output
/usr/bin/install -d -m 0700 \
    "${source_root}/etc/plntir" \
    "${source_root}/opt/plntir" \
    "${source_root}/var/lib/plntir/monitor" \
    "${source_root}/var/lib/plntir-web" \
    "${state_dir}" "${output_dir}"
/usr/bin/touch \
    "${source_root}/etc/plntir/managed-endpoint.conf" \
    "${source_root}/opt/plntir/plntir-test" \
    "${source_root}/var/lib/plntir/monitor/mac-latest.json" \
    "${source_root}/var/lib/plntir-web/audit.jsonl"

/usr/bin/age-keygen -o "${workdir}/identity.txt" >/dev/null 2>&1
/usr/bin/age-keygen -y "${workdir}/identity.txt" >"${workdir}/recipient.txt"

validate_config() {
    PLNTIR_TEST_MARKER=${PLNTIR_TEST_MARKER:-} \
        PLNTIR_BACKUP_TESTING=1 \
        PLNTIR_BACKUP_SOURCE_ROOT="${source_root}" \
        PLNTIR_BACKUP_STATE_DIR="${state_dir}" \
        PLNTIR_BACKUP_RECIPIENT_FILE="${workdir}/recipient.txt" \
        PLNTIR_BACKUP_CONFIG_FILE=$1 \
        "${ROOT}/control-node/bin/plntir-control-plane-backup" \
        --validate-config
}

valid_config=${workdir}/valid.env
/usr/bin/printf '%s\n' \
    R2_ACCOUNT_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    R2_BUCKET=plntir-control-plane-backups \
    R2_JURISDICTION=default \
    R2_ACCESS_KEY_ID=AAAAAAAAAAAAAAAA \
    R2_SECRET_ACCESS_KEY=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
    >"${valid_config}"
validate_config "${valid_config}" >/dev/null

duplicate_config=${workdir}/duplicate.env
/bin/cp "${valid_config}" "${duplicate_config}"
/usr/bin/printf '%s\n' R2_BUCKET=second-bucket >>"${duplicate_config}"
if validate_config "${duplicate_config}" >/dev/null 2>&1; then
    printf 'Duplicate R2 configuration key unexpectedly passed validation.\n' >&2
    exit 1
fi

marker=${workdir}/config-was-executed
injection_config=${workdir}/injection.env
/usr/bin/printf '%s\n' \
    R2_ACCOUNT_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    'R2_BUCKET=$(touch${IFS}${PLNTIR_TEST_MARKER})' \
    R2_JURISDICTION=default \
    R2_ACCESS_KEY_ID=AAAAAAAAAAAAAAAA \
    R2_SECRET_ACCESS_KEY=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
    >"${injection_config}"
if PLNTIR_TEST_MARKER="${marker}" validate_config "${injection_config}" >/dev/null 2>&1; then
    printf 'Executable-looking R2 configuration unexpectedly passed validation.\n' >&2
    exit 1
fi
[[ ! -e ${marker} ]] || {
    printf 'R2 configuration content was executed.\n' >&2
    exit 1
}

PLNTIR_BACKUP_TESTING=1 \
    PLNTIR_BACKUP_SOURCE_ROOT="${source_root}" \
    PLNTIR_BACKUP_STATE_DIR="${state_dir}" \
    PLNTIR_BACKUP_RECIPIENT_FILE="${workdir}/recipient.txt" \
    "${ROOT}/control-node/bin/plntir-control-plane-backup" \
    --local-output "${output_dir}" >/dev/null

archive=$(/usr/bin/find "${output_dir}" -maxdepth 1 -type f -name '*.tar.gz.age' -print -quit)
[[ -n ${archive} ]]
"${ROOT}/scripts/verify-plntir-control-plane-backup.sh" \
    "${archive}" "${workdir}/identity.txt" >/dev/null
/usr/bin/jq -e '.state == "complete" and .stage == "local"' \
    "${state_dir}/status.json" >/dev/null
/usr/bin/age --decrypt -i "${workdir}/identity.txt" "${archive}" |
    /usr/bin/tar -tzf - |
    /usr/bin/grep -Fxq 'var/lib/plntir-web/audit.jsonl'

tampered=${workdir}/tampered.tar.gz.age
/bin/cp "${archive}" "${tampered}"
/usr/bin/printf 'tamper\n' >>"${tampered}"
if "${ROOT}/scripts/verify-plntir-control-plane-backup.sh" \
    "${tampered}" "${workdir}/identity.txt" >/dev/null 2>&1; then
    printf 'Tampered encrypted backup unexpectedly passed verification.\n' >&2
    exit 1
fi

printf 'Off-host backup checks passed.\n'
