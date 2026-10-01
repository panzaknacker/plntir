#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on plntir-mdm-01.\n' >&2
    exit 1
fi

readonly ENV_FILE=/etc/plntir/fleet/fleet.env
readonly INSTALL_DIR=/opt/plntir/device-management
readonly COMPOSE_FILE=${INSTALL_DIR}/compose.yaml
compose=(
    /usr/bin/docker compose
    --env-file "${ENV_FILE}"
    -f "${COMPOSE_FILE}"
)

failed=0
check() {
    local description=$1
    shift
    if "$@" >/dev/null 2>&1; then
        printf 'PASS %s\n' "${description}"
    else
        printf 'FAIL %s\n' "${description}" >&2
        failed=1
    fi
}

check 'Fleet environment is root-only' sh -c \
    "test \"\$(stat -Lc '%u:%g:%a' '${ENV_FILE}')\" = 0:0:600"
for protected_file in \
    "${COMPOSE_FILE}" \
    "${INSTALL_DIR}/public-routes-v4.89.2.json" \
    "${INSTALL_DIR}/ingress_proxy.go" \
    "${INSTALL_DIR}/ingress_proxy_test.go" \
    "${INSTALL_DIR}/go.mod" \
    "${INSTALL_DIR}/ingress-proxy/Dockerfile"; do
    check "$(/usr/bin/basename "${protected_file}") is protected" sh -c \
        "test \"\$(stat -Lc '%u:%g:%a' '${protected_file}')\" = 0:0:640"
done
check 'Compose model resolves' "${compose[@]}" config --quiet
check 'Fleet health endpoint responds' /usr/bin/curl -fsS \
    http://127.0.0.1:1337/healthz
check 'Ingress self-health responds' "${compose[@]}" exec -T ingress \
    /usr/local/bin/plntir-fleet-ingress healthcheck
for service in mysql redis fleet ingress; do
    check "${service} container is running" sh -c \
        "${compose[*]} ps --status running --services | grep -Fxq '${service}'"
done
check 'Fleet UI is loopback-only in private staging' sh -c \
    "test \"\$(${compose[*]} port fleet 8080)\" = 127.0.0.1:1337"
check 'Device ingress is loopback-only in private staging' sh -c \
    "test \"\$(${compose[*]} port ingress 8080)\" = 127.0.0.1:1338"
check 'MySQL has no published host port' sh -c \
    "test -z \"\$(${compose[*]} port mysql 3306 2>/dev/null || true)\""
check 'Redis has no published host port' sh -c \
    "test -z \"\$(${compose[*]} port redis 6379 2>/dev/null || true)\""
check 'Unknown device path is denied' sh -c \
    "test \"\$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' -H 'Host: mdm.plntir.example' http://127.0.0.1:1338/)\" = 404"
check 'Known path with wrong method is denied' sh -c \
    "test \"\$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' -H 'Host: mdm.plntir.example' http://127.0.0.1:1338/api/fleet/orbit/config)\" = 404"
check 'Wrong hostname is denied' sh -c \
    "test \"\$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' -X POST -H 'Host: admin.plntir.example' http://127.0.0.1:1338/api/fleet/orbit/config)\" = 404"

exit "${failed}"
