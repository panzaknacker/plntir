#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the new plntir-mdm-01 node.\n' >&2
    exit 1
fi
if [[ $(/usr/bin/uname -s) != Linux || $(/usr/bin/uname -m) != x86_64 ]]; then
    printf 'This pinned Fleet base supports Linux on x86_64 only.\n' >&2
    exit 69
fi
if [[ $(/usr/bin/hostname -s) != plntir-mdm-01 ]]; then
    printf 'Refusing to install outside the new plntir-mdm-01 node.\n' >&2
    exit 69
fi
if [[ $# -ne 1 ]]; then
    printf 'usage: %s BUNDLE_DIR\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly SOURCE_DIR=${BUNDLE_DIR}/mdm/fleet
readonly COMPOSE_SOURCE=${SOURCE_DIR}/compose.yaml
readonly POLICY_SOURCE=${SOURCE_DIR}/public-routes-v4.89.2.json
readonly PROXY_GO_SOURCE=${SOURCE_DIR}/ingress_proxy.go
readonly PROXY_TEST_SOURCE=${SOURCE_DIR}/ingress_proxy_test.go
readonly GO_MOD_SOURCE=${SOURCE_DIR}/go.mod
readonly DOCKERFILE_SOURCE=${SOURCE_DIR}/ingress-proxy/Dockerfile
readonly VERIFY_SOURCE=${BUNDLE_DIR}/scripts/verify-plntir-device-management-base.sh
readonly CONFIG_DIR=/etc/plntir/fleet
readonly ENV_FILE=${CONFIG_DIR}/fleet.env
readonly INSTALL_DIR=/opt/plntir/device-management
readonly COMPOSE_FILE=${INSTALL_DIR}/compose.yaml
readonly VERIFY_TARGET=${INSTALL_DIR}/verify-base

required_inputs=(
    "${BUNDLE_DIR}"
    "${SOURCE_DIR}"
    "${COMPOSE_SOURCE}"
    "${POLICY_SOURCE}"
    "${PROXY_GO_SOURCE}"
    "${PROXY_TEST_SOURCE}"
    "${GO_MOD_SOURCE}"
    "${DOCKERFILE_SOURCE}"
    "${VERIFY_SOURCE}"
)
for path in "${required_inputs[@]}"; do
    [[ -e ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe MDM base input: %s\n' "${path}" >&2
        exit 66
    }
done
[[ -d ${BUNDLE_DIR} && -d ${SOURCE_DIR} ]] || exit 66
[[ $(/usr/bin/stat -Lc %u "${BUNDLE_DIR}") -eq 0 ]] || {
    printf 'MDM bundle must be root-owned.\n' >&2
    exit 77
}
unsafe_path=$(/usr/bin/find "${BUNDLE_DIR}" \( -perm -0020 -o -perm -0002 \) -print -quit)
[[ -z ${unsafe_path} ]] || {
    printf 'MDM bundle contains a group/other-writable path: %s\n' "${unsafe_path}" >&2
    exit 77
}
/usr/bin/docker --version >/dev/null
/usr/bin/docker compose version >/dev/null
/usr/bin/openssl version >/dev/null
/usr/bin/curl --version >/dev/null

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly STAMP
readonly BACKUP_DIR=/var/backups/plntir/${STAMP}-device-management-base
/usr/bin/install -d -m 0700 "${BACKUP_DIR}"
for target in \
    "${ENV_FILE}" \
    "${COMPOSE_FILE}" \
    "${INSTALL_DIR}/public-routes-v4.89.2.json" \
    "${INSTALL_DIR}/ingress_proxy.go" \
    "${INSTALL_DIR}/ingress_proxy_test.go" \
    "${INSTALL_DIR}/go.mod" \
    "${INSTALL_DIR}/ingress-proxy/Dockerfile" \
    "${VERIFY_TARGET}"; do
    if [[ -e ${target} ]]; then
        /bin/cp -a "${target}" "${BACKUP_DIR}/$(/usr/bin/basename "${target}").before"
    fi
done

/usr/bin/install -d -o root -g root -m 0700 "${CONFIG_DIR}"
/usr/bin/install -d -o root -g root -m 0750 "${INSTALL_DIR}"
/usr/bin/install -d -o root -g root -m 0750 "${INSTALL_DIR}/ingress-proxy"
/usr/bin/install -o root -g root -m 0640 "${COMPOSE_SOURCE}" "${COMPOSE_FILE}"
/usr/bin/install -o root -g root -m 0640 "${POLICY_SOURCE}" \
    "${INSTALL_DIR}/public-routes-v4.89.2.json"
/usr/bin/install -o root -g root -m 0640 "${PROXY_GO_SOURCE}" \
    "${INSTALL_DIR}/ingress_proxy.go"
/usr/bin/install -o root -g root -m 0640 "${PROXY_TEST_SOURCE}" \
    "${INSTALL_DIR}/ingress_proxy_test.go"
/usr/bin/install -o root -g root -m 0640 "${GO_MOD_SOURCE}" "${INSTALL_DIR}/go.mod"
/usr/bin/install -o root -g root -m 0640 "${DOCKERFILE_SOURCE}" \
    "${INSTALL_DIR}/ingress-proxy/Dockerfile"
/usr/bin/install -o root -g root -m 0750 "${VERIFY_SOURCE}" "${VERIFY_TARGET}"

if [[ -e ${ENV_FILE} ]]; then
    [[ -f ${ENV_FILE} && ! -L ${ENV_FILE} ]] || {
        printf 'Existing Fleet environment is unsafe.\n' >&2
        exit 77
    }
    [[ $(/usr/bin/stat -Lc '%u:%g:%a' "${ENV_FILE}") == 0:0:600 ]] || {
        printf 'Existing Fleet environment must be root:root mode 0600.\n' >&2
        exit 77
    }
    for required_line in \
        'FLEET_HOSTNAME=mdm.plntir.example' \
        'FLEET_ADMIN_BIND_ADDRESS=127.0.0.1' \
        'FLEET_DEVICE_BIND_ADDRESS=127.0.0.1'; do
        /usr/bin/grep -Fxq "${required_line}" "${ENV_FILE}" || {
            printf 'Private staging requires %s in %s.\n' \
                "${required_line}" "${ENV_FILE}" >&2
            exit 78
        }
    done
else
    env_tmp=$(/usr/bin/mktemp "${CONFIG_DIR}/.fleet.env.XXXXXX")
    trap '/bin/rm -f "${env_tmp}"' EXIT
    mysql_root_password=$(/usr/bin/openssl rand -hex 32)
    mysql_password=$(/usr/bin/openssl rand -hex 32)
    fleet_server_private_key=$(/usr/bin/openssl rand -base64 48 | /usr/bin/tr -d '\n')
    {
        printf 'FLEET_HOSTNAME=mdm.plntir.example\n'
        printf 'FLEET_ADMIN_BIND_ADDRESS=127.0.0.1\n'
        printf 'FLEET_DEVICE_BIND_ADDRESS=127.0.0.1\n'
        printf 'MYSQL_ROOT_PASSWORD=%s\n' "${mysql_root_password}"
        printf 'MYSQL_PASSWORD=%s\n' "${mysql_password}"
        printf 'FLEET_SERVER_PRIVATE_KEY=%s\n' "${fleet_server_private_key}"
    } >"${env_tmp}"
    unset mysql_root_password mysql_password fleet_server_private_key
    /bin/chown root:root "${env_tmp}"
    /bin/chmod 0600 "${env_tmp}"
    /bin/mv -f "${env_tmp}" "${ENV_FILE}"
    trap - EXIT
fi

compose=(
    /usr/bin/docker compose
    --env-file "${ENV_FILE}"
    -f "${COMPOSE_FILE}"
)
"${compose[@]}" config --quiet

for port in 1337 1338; do
    listener=$(/usr/bin/ss -H -ltn "sport = :${port}" || true)
    if [[ -n ${listener} ]]; then
        if [[ ${port} == 1337 ]]; then
            service=fleet
            expected_binding=127.0.0.1:1337
        else
            service=ingress
            expected_binding=127.0.0.1:1338
        fi
        existing_binding=$("${compose[@]}" port "${service}" 8080 2>/dev/null || true)
        if [[ ${existing_binding} != "${expected_binding}" ]]; then
            printf 'TCP port %s is already used outside this private Fleet stack.\n' \
                "${port}" >&2
            exit 75
        fi
    fi
done

"${compose[@]}" pull --ignore-buildable
"${compose[@]}" build --pull ingress
"${compose[@]}" up -d

healthy=false
for _attempt in {1..60}; do
    if /usr/bin/curl -fsS http://127.0.0.1:1337/healthz >/dev/null 2>&1 &&
        "${compose[@]}" exec -T ingress \
            /usr/local/bin/plntir-fleet-ingress healthcheck >/dev/null 2>&1; then
        healthy=true
        break
    fi
    /bin/sleep 5
done
[[ ${healthy} == true ]] || {
    printf 'Fleet or its exact ingress proxy did not become healthy within five minutes.\n' >&2
    "${compose[@]}" ps >&2 || true
    exit 75
}

"${VERIFY_TARGET}"
printf 'Plntir MDM private base is ready. UI: 127.0.0.1:1337; device proxy: 127.0.0.1:1338.\n'
printf 'No public Tunnel, DNS record, APNs credential, enrollment, or disk-encryption change was made.\n'
printf 'Backup: %s\n' "${BACKUP_DIR}"
