#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT

test_root=${workdir}/root
state_dir=${workdir}/state
target=${test_root}/usr/local/libexec/plntir-test
/usr/bin/install -d -m 0755 "$(/usr/bin/dirname "${target}")" "${state_dir}"
/usr/bin/printf '#!/bin/sh\nprintf test\\n\n' >"${target}"
/bin/chmod 0755 "${target}"

hash=$(/usr/bin/sha256sum "${target}" | /usr/bin/awk '{print $1}')
mode=$(/usr/bin/stat -c %a "${target}")
owner=$(/usr/bin/stat -c %U "${target}")
group=$(/usr/bin/stat -c %G "${target}")
/usr/bin/printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${hash}" "${mode}" "${owner}" "${group}" "${target}" files/0001 \
    >"${state_dir}/baseline.tsv"
/usr/bin/printf 'test-release\n' >"${state_dir}/release-id"

run_check() {
    PLNTIR_INTEGRITY_TESTING=1 \
        PLNTIR_INTEGRITY_TEST_ROOT="${test_root}" \
        PLNTIR_INTEGRITY_STATE_DIR="${state_dir}" \
        PLNTIR_INTEGRITY_MANIFEST="${state_dir}/baseline.tsv" \
        "${ROOT}/mac/libexec/plntir-integrity-check" --check
}

run_check
/usr/bin/grep -Fxq 'integrity_state=healthy' "${state_dir}/status.env"
/usr/bin/grep -Fxq 'integrity_mode=alert-only' "${state_dir}/status.env"

/usr/bin/printf '# drift\n' >>"${target}"
run_check
/usr/bin/grep -Fxq 'integrity_state=drift' "${state_dir}/status.env"
/usr/bin/grep -Fxq 'integrity_drift_count=1' "${state_dir}/status.env"
/usr/bin/grep -Fq $'content_hash\t' "${state_dir}/drift.tsv"

/usr/bin/printf 'malformed baseline\n' >"${state_dir}/baseline.tsv"
if run_check >/dev/null 2>&1; then
    printf 'Malformed integrity baseline unexpectedly passed.\n' >&2
    exit 1
fi
/usr/bin/grep -Fxq 'integrity_state=error' "${state_dir}/status.env"
/usr/bin/grep -Fq $'unsafe_manifest_entry\t-' "${state_dir}/drift.tsv"

printf 'Integrity checks passed.\n'
