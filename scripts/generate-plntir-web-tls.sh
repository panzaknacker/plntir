#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    printf 'usage: %s OUTPUT_DIRECTORY MESH_IP\n' "$0" >&2
    exit 64
fi

readonly OUTPUT=$1
readonly MESH_IP=$2
[[ ${MESH_IP} =~ ^[0-9]{1,3}([.][0-9]{1,3}){3}$ ]] || {
    printf 'MESH_IP must be IPv4.\n' >&2
    exit 64
}
IFS=. read -r first second third fourth <<<"${MESH_IP}"
first=$((10#${first}))
second=$((10#${second}))
third=$((10#${third}))
fourth=$((10#${fourth}))
[[ ${first} -eq 100 && ${second} -ge 96 && ${second} -le 111 &&
    ${third} -ge 0 && ${third} -le 255 && ${fourth} -ge 1 && ${fourth} -le 254 ]] || {
    printf 'MESH_IP must be inside the configured 100.96.0.0/12 Mesh range.\n' >&2
    exit 77
}
[[ ! -e ${OUTPUT} && ! -L ${OUTPUT} ]] || {
    printf 'Refusing existing TLS output directory: %s\n' "${OUTPUT}" >&2
    exit 73
}

/usr/bin/install -d -m 0700 "${OUTPUT}"
work=$(/usr/bin/mktemp -d)
cleanup() {
    case ${work} in
    /tmp/* | /var/tmp/*) /bin/rm -rf "${work}" ;;
    esac
}
trap cleanup EXIT HUP INT TERM

/usr/bin/openssl genpkey -algorithm ED25519 -out "${OUTPUT}/plntir-web-ca.key"
/usr/bin/openssl req -x509 -new -sha256 -days 3650 \
    -key "${OUTPUT}/plntir-web-ca.key" \
    -subj '/O=Plntir/CN=Plntir Private Web CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "${OUTPUT}/plntir-web-ca.crt"

/usr/bin/openssl genpkey -algorithm ED25519 -out "${OUTPUT}/plntir-web-server.key"
/usr/bin/openssl req -new \
    -key "${OUTPUT}/plntir-web-server.key" \
    -subj '/O=Plntir/CN=Plntir Mesh Operations Console' \
    -out "${work}/server.csr"
printf '%s\n' \
    '[server]' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=IP:${MESH_IP}" \
    >"${work}/server.ext"
/usr/bin/openssl x509 -req -sha256 -days 825 \
    -in "${work}/server.csr" \
    -CA "${OUTPUT}/plntir-web-ca.crt" \
    -CAkey "${OUTPUT}/plntir-web-ca.key" \
    -CAcreateserial \
    -extfile "${work}/server.ext" \
    -extensions server \
    -out "${OUTPUT}/plntir-web-server.crt"
/bin/rm -f "${OUTPUT}/plntir-web-ca.srl"
/bin/chmod 0600 "${OUTPUT}/plntir-web-ca.key" "${OUTPUT}/plntir-web-server.key"
/bin/chmod 0644 "${OUTPUT}/plntir-web-ca.crt" "${OUTPUT}/plntir-web-server.crt"

/usr/bin/openssl verify -CAfile "${OUTPUT}/plntir-web-ca.crt" \
    -verify_ip "${MESH_IP}" "${OUTPUT}/plntir-web-server.crt"
printf 'TLS kit created in %s\n' "${OUTPUT}"
printf 'Import plntir-web-ca.crt only on authorized operator devices.\n'
printf 'Keep plntir-web-ca.key off the Control Node in the encrypted operator vault.\n'
