#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'usage: %s OUTPUT_AUTH_JSON [USERNAME]\n' "$0" >&2
    exit 64
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly OUTPUT=$1
readonly USERNAME=${2:-operator}
readonly BINARY=${ROOT}/bin/plntir-web

[[ ${USERNAME} =~ ^[A-Za-z0-9._-]{1,64}$ ]] || {
    printf 'Invalid dashboard username.\n' >&2
    exit 64
}
[[ -x ${BINARY} ]] || {
    printf 'Build the dashboard first with: make plntir-web\n' >&2
    exit 66
}
[[ ! -e ${OUTPUT} && ! -L ${OUTPUT} ]] || {
    printf 'Refusing existing auth path: %s\n' "${OUTPUT}" >&2
    exit 73
}

password=''
confirm=''
cleanup() {
    unset password confirm
}
trap cleanup EXIT HUP INT TERM

printf 'Create a separate dashboard password; do not reuse the Mac administrator password.\n'
IFS= read -r -s -p 'Dashboard password (minimum 16 characters): ' password </dev/tty
printf '\n'
IFS= read -r -s -p 'Repeat dashboard password: ' confirm </dev/tty
printf '\n'
[[ ${password} == "${confirm}" ]] || {
    printf 'Passwords do not match.\n' >&2
    exit 77
}

parent=$(cd "$(dirname "${OUTPUT}")" && pwd -P)
readonly parent
temporary=$(/usr/bin/mktemp "${parent}/.plntir-web-auth.XXXXXX")
trap 'cleanup; /bin/rm -f "${temporary}"' EXIT HUP INT TERM
/bin/chmod 0600 "${temporary}"
printf '%s\n' "${password}" | "${BINARY}" hash-password --username "${USERNAME}" >"${temporary}"
unset password confirm
/usr/bin/jq -e \
    '.schema_version == 1 and (.username | type == "string") and (.password_hash | startswith("pbkdf2-sha256$"))' \
    "${temporary}" >/dev/null
/bin/mv "${temporary}" "${OUTPUT}"
trap - EXIT HUP INT TERM
printf 'Dashboard auth file created: %s\n' "${OUTPUT}"
