#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    printf 'usage: %s ENCRYPTED_BACKUP AGE_IDENTITY\n' "$0" >&2
    exit 64
fi
readonly ARCHIVE=$1
readonly IDENTITY=$2
[[ -f ${ARCHIVE} && ! -L ${ARCHIVE} ]] || exit 66
[[ -f ${IDENTITY} && ! -L ${IDENTITY} ]] || exit 66

workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT
plain=${workdir}/backup.tar.gz
/usr/bin/age --decrypt -i "${IDENTITY}" -o "${plain}" "${ARCHIVE}"

listing=${workdir}/listing.txt
/usr/bin/tar -tzf "${plain}" >"${listing}"
if /usr/bin/grep -Eq '(^/|(^|/)[.][.](/|$))' "${listing}"; then
    printf 'Unsafe path found in decrypted backup.\n' >&2
    exit 65
fi
for required in \
    etc/plntir/ \
    opt/plntir/ \
    var/lib/plntir/monitor/ \
    metadata/manifest.json \
    metadata/path-list.txt; do
    /usr/bin/grep -Fqx "${required}" "${listing}" || {
        printf 'Backup is missing required entry: %s\n' "${required}" >&2
        exit 66
    }
done
/usr/bin/tar -xOf "${plain}" metadata/manifest.json | /usr/bin/jq -e \
    '.schema_version == 1 and .encryption == "age-x25519" and .scope == "plntir-control-plane-no-user-content"' \
    >/dev/null

printf 'Encrypted Plntir control-plane backup verified.\n'
