#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly GPG_HOME=${ROOT}/secrets/plntir_secure_archive_gnupg
readonly PASSPHRASE_FILE=${ROOT}/secrets/plntir_secure_archive.passphrase

if [[ $# -lt 2 || $# -gt 3 ]]; then
    printf 'usage: %s --verify ARCHIVE | --decrypt ARCHIVE OUTPUT.tar\n' "$0" >&2
    exit 64
fi
readonly MODE=$1
readonly ARCHIVE=$2
[[ -f ${ARCHIVE} && ! -L ${ARCHIVE} ]] || {
    printf 'Archive is missing or unsafe.\n' >&2
    exit 66
}
[[ -d ${GPG_HOME} && ! -L ${GPG_HOME} && -f ${PASSPHRASE_FILE} && ! -L ${PASSPHRASE_FILE} ]] || {
    printf 'Local archive decryption material is missing.\n' >&2
    exit 66
}

decrypt=(
    /usr/bin/gpg
    --homedir "${GPG_HOME}"
    --batch
    --no-tty
    --pinentry-mode loopback
    --passphrase-file "${PASSPHRASE_FILE}"
    --decrypt "${ARCHIVE}"
)

case ${MODE} in
--verify)
    [[ $# -eq 2 ]] || exit 64
    "${decrypt[@]}" | /usr/bin/zstd -q -d | /usr/bin/tar -tf - >/dev/null
    printf 'Encrypted archive decrypted and tar structure verified.\n'
    ;;
--decrypt)
    [[ $# -eq 3 ]] || exit 64
    readonly OUTPUT=$3
    [[ ! -e ${OUTPUT} && ! -L ${OUTPUT} ]] || {
        printf 'Output already exists: %s\n' "${OUTPUT}" >&2
        exit 73
    }
    incomplete=${OUTPUT}.partial.$$
    cleanup() {
        local rc=$?
        trap - EXIT
        /bin/rm -f "${incomplete}"
        exit "${rc}"
    }
    trap cleanup EXIT
    "${decrypt[@]}" | /usr/bin/zstd -q -d >"${incomplete}"
    /bin/chmod 0600 "${incomplete}"
    /bin/mv -f "${incomplete}" "${OUTPUT}"
    trap - EXIT
    printf 'Decrypted tar archive: %s\n' "${OUTPUT}"
    ;;
*)
    exit 64
    ;;
esac
