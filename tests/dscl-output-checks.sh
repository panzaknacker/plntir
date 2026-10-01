#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
# shellcheck source=scripts/plntir-dscl-output.sh
source "${ROOT}/scripts/plntir-dscl-output.sh"

readonly EXPECTED='Plntir Endpoint Agent'
fixtures=(
    'RealName: Plntir Endpoint Agent'
    $'RealName:\n Plntir Endpoint Agent'
    $'RealName:\n\tPlntir Endpoint Agent'
)
for fixture in "${fixtures[@]}"; do
    /usr/bin/printf '%s\n' "${fixture}" |
        plntir_dscl_output_has_value "${EXPECTED}"
done

bad_fixtures=(
    'RealName: Plntir Endpoint'
    'RealName: Plntir Endpoint Agent Extra'
    $'RealName:\n Plntir Endpoint Agent\n Unexpected second value'
    'RealName:'
)
for fixture in "${bad_fixtures[@]}"; do
    if /usr/bin/printf '%s\n' "${fixture}" |
        plntir_dscl_output_has_value "${EXPECTED}"; then
        printf 'Invalid dscl fixture was accepted: %q\n' "${fixture}" >&2
        exit 1
    fi
done

printf 'dscl output checks passed.\n'
