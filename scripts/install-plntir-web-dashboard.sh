#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi
if [[ $# -ne 6 ]]; then
    printf 'usage: %s BUNDLE_DIR MESH_IP TLS_CA_CERT TLS_CERT TLS_KEY AUTH_JSON\n' "$0" >&2
    exit 64
fi

BUNDLE=$(cd "$1" && pwd -P) || {
    printf 'Bundle directory is unavailable.\n' >&2
    exit 66
}
readonly BUNDLE
readonly MESH_IP=$2
readonly TLS_CA_CERT=$3
readonly TLS_CERT=$4
readonly TLS_KEY=$5
readonly AUTH_JSON=$6
readonly WEB_USER=plntirweb
readonly WEB_GROUP=plntirweb
readonly CONTROL_GROUP=plntircontrol
readonly CONFIG_LOADER=/opt/plntir/lib/managed-endpoint-config.sh
readonly AUDIT_FILE=/var/lib/plntir-web/audit.jsonl

checksum_targets=(
    bin/plntir-web
    client/internal/collector/plntir-status-v2.sh
    control-node/bin/plntir-control-plane-backup
    control-node/bin/plntir-endpoint-retrieve
    control-node/bin/plntir-web-action
    control-node/sudoers/91-plntir-web
    control-node/systemd/plntir-web.service
    config/nftables/nftables.conf
    docs/plntir-web-dashboard.md
    scripts/install-plntir-web-dashboard.sh
    scripts/verify-plntir-web-dashboard.sh
)
required=("${checksum_targets[@]}" SHA256SUMS)
for relative in "${required[@]}"; do
    [[ -f ${BUNDLE}/${relative} && ! -L ${BUNDLE}/${relative} ]] || {
        printf 'Missing or unsafe bundle file: %s\n' "${relative}" >&2
        exit 66
    }
done
[[ $(/usr/bin/wc -l <"${BUNDLE}/SHA256SUMS") -eq ${#checksum_targets[@]} ]] || {
    printf 'Unexpected dashboard bundle checksum manifest length.\n' >&2
    exit 65
}
for relative in "${checksum_targets[@]}"; do
    /usr/bin/awk -v expected="${relative}" '
        $1 ~ /^[a-f0-9]{64}$/ && $2 == expected {found = 1}
        END {exit !found}
    ' "${BUNDLE}/SHA256SUMS" || {
        printf 'Missing checksum for bundle file: %s\n' "${relative}" >&2
        exit 65
    }
done
(
    cd "${BUNDLE}"
    /usr/bin/sha256sum --check --strict SHA256SUMS
) >/dev/null || {
    printf 'Dashboard bundle checksum verification failed.\n' >&2
    exit 74
}
for input in "${TLS_CA_CERT}" "${TLS_CERT}" "${TLS_KEY}" "${AUTH_JSON}"; do
    [[ -f ${input} && ! -L ${input} ]] || {
        printf 'Missing or unsafe input file: %s\n' "${input}" >&2
        exit 66
    }
done
[[ -r ${CONFIG_LOADER} ]] || {
    printf 'Managed endpoint configuration is not installed.\n' >&2
    exit 69
}

[[ ${MESH_IP} =~ ^[0-9]{1,3}([.][0-9]{1,3}){3}$ ]] || exit 64
IFS=. read -r first second third fourth <<<"${MESH_IP}"
first=$((10#${first}))
second=$((10#${second}))
third=$((10#${third}))
fourth=$((10#${fourth}))
[[ ${first} -eq 100 && ${second} -ge 96 && ${second} -le 111 &&
    ${third} -ge 0 && ${third} -le 255 && ${fourth} -ge 1 && ${fourth} -le 254 ]] || {
    printf 'MESH_IP is outside 100.96.0.0/12.\n' >&2
    exit 77
}
/usr/sbin/ip -4 -o address show dev CloudflareWARP |
    /usr/bin/awk '{sub(/\/.*/, "", $4); print $4}' |
    /usr/bin/grep -Fxq "${MESH_IP}" || {
    printf 'MESH_IP is not assigned to CloudflareWARP.\n' >&2
    exit 77
}

/usr/bin/openssl x509 -in "${TLS_CERT}" -noout -checkend 604800 >/dev/null || {
    printf 'TLS certificate expires in less than seven days.\n' >&2
    exit 77
}
/usr/bin/openssl verify -CAfile "${TLS_CA_CERT}" -verify_ip "${MESH_IP}" \
    "${TLS_CERT}" >/dev/null || {
    printf 'TLS certificate does not verify against the supplied private CA and Mesh IP.\n' >&2
    exit 77
}
cert_pub=$(/usr/bin/openssl x509 -in "${TLS_CERT}" -pubkey -noout | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
key_pub=$(/usr/bin/openssl pkey -in "${TLS_KEY}" -pubout | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
[[ ${cert_pub} == "${key_pub}" ]] || {
    printf 'TLS certificate and key do not match.\n' >&2
    exit 77
}
/usr/bin/openssl x509 -in "${TLS_CERT}" -noout -text |
    /usr/bin/grep -Fq "IP Address:${MESH_IP}" || {
    printf 'TLS certificate does not contain the Mesh IP SAN.\n' >&2
    exit 77
}
/usr/bin/jq -e \
    '.schema_version == 1 and (.username | test("^[A-Za-z0-9._-]{1,64}$")) and (.password_hash | test("^pbkdf2-sha256\\$[0-9]+\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$"))' \
    "${AUTH_JSON}" >/dev/null || {
    printf 'Invalid dashboard auth file.\n' >&2
    exit 65
}

# shellcheck source=/dev/null
source "${CONFIG_LOADER}"
load_managed_mac_config
readonly MANAGED_HOME=${MAC_MANAGED_HOME}

STAMP=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly BACKUP=/var/backups/plntir/${STAMP}-web-dashboard
/usr/bin/install -d -m 0700 "${BACKUP}"
for target in \
    /opt/plntir/bin/plntir-web \
    /opt/plntir/bin/status-v2 \
    /opt/plntir/bin/plntir-control-plane-backup \
    /opt/plntir/bin/plntir-endpoint-retrieve \
    /opt/plntir/bin/plntir-web-action \
    /etc/sudoers.d/91-plntir-web \
    /etc/systemd/system/plntir-web.service \
    /etc/plntir/web-console.json \
    /etc/plntir/web/ca.crt \
    /etc/plntir/web/tls.crt \
    /etc/plntir/web/tls.key \
    /etc/plntir/web/auth.json \
    /etc/nftables.conf; do
    if [[ -e ${target} ]]; then
        /usr/bin/install -D -m 0600 "${target}" "${BACKUP}${target}"
    fi
done

if ! /usr/bin/getent group "${WEB_GROUP}" >/dev/null; then
    /usr/sbin/groupadd --system "${WEB_GROUP}"
fi
if ! /usr/bin/id "${WEB_USER}" >/dev/null 2>&1; then
    /usr/sbin/useradd --system --gid "${WEB_GROUP}" --create-home \
        --home-dir /var/lib/plntir-web --shell /usr/sbin/nologin \
        --comment 'Plntir Web Console Service' "${WEB_USER}"
fi
/usr/sbin/usermod --comment 'Plntir Web Console Service' "${WEB_USER}"
/usr/sbin/usermod -a -G "${CONTROL_GROUP}" "${WEB_USER}"
/usr/bin/passwd -l "${WEB_USER}" >/dev/null

/usr/bin/install -d -o root -g root -m 0755 /opt/plntir/share /opt/plntir/share/docs
/usr/bin/install -d -o root -g "${WEB_GROUP}" -m 0750 /etc/plntir/web
/usr/bin/install -d -o "${WEB_USER}" -g "${WEB_GROUP}" -m 0700 /var/lib/plntir-web
if [[ -e ${AUDIT_FILE} || -L ${AUDIT_FILE} ]]; then
    [[ -f ${AUDIT_FILE} && ! -L ${AUDIT_FILE} ]] || {
        printf 'Existing dashboard audit path is unsafe.\n' >&2
        exit 77
    }
else
    /usr/bin/install -o "${WEB_USER}" -g "${WEB_GROUP}" -m 0600 /dev/null "${AUDIT_FILE}"
fi
/bin/chown "${WEB_USER}:${WEB_GROUP}" "${AUDIT_FILE}"
/bin/chmod 0600 "${AUDIT_FILE}"
/usr/bin/install -o root -g root -m 0755 \
    "${BUNDLE}/bin/plntir-web" /opt/plntir/bin/plntir-web
/usr/bin/install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE}/client/internal/collector/plntir-status-v2.sh" /opt/plntir/bin/status-v2
/usr/bin/install -o root -g "${CONTROL_GROUP}" -m 0750 \
    "${BUNDLE}/control-node/bin/plntir-control-plane-backup" /opt/plntir/bin/plntir-control-plane-backup
/usr/bin/install -o root -g root -m 0755 \
    "${BUNDLE}/control-node/bin/plntir-endpoint-retrieve" /opt/plntir/bin/plntir-endpoint-retrieve
/usr/bin/install -o root -g root -m 0755 \
    "${BUNDLE}/control-node/bin/plntir-web-action" /opt/plntir/bin/plntir-web-action
/usr/bin/install -o root -g root -m 0440 \
    "${BUNDLE}/control-node/sudoers/91-plntir-web" /etc/sudoers.d/91-plntir-web
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE}/control-node/systemd/plntir-web.service" /etc/systemd/system/plntir-web.service
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE}/docs/plntir-web-dashboard.md" /opt/plntir/share/docs/plntir-web-dashboard.md
/usr/bin/install -o root -g root -m 0644 "${TLS_CERT}" /etc/plntir/web/tls.crt
/usr/bin/install -o root -g root -m 0644 "${TLS_CA_CERT}" /etc/plntir/web/ca.crt
/usr/bin/install -o root -g "${WEB_GROUP}" -m 0640 "${TLS_KEY}" /etc/plntir/web/tls.key
/usr/bin/install -o root -g "${WEB_GROUP}" -m 0640 "${AUTH_JSON}" /etc/plntir/web/auth.json

config_tmp=$(/usr/bin/mktemp /etc/plntir/.web-console.XXXXXX)
trap '/bin/rm -f "${config_tmp}"' EXIT
/usr/bin/jq -cn \
    --arg listen "${MESH_IP}:8443" \
    --arg host "${MESH_IP}:8443" \
    --arg home "${MANAGED_HOME}" \
    '{
        listen:$listen,
        allowed_mesh_cidr:"100.96.0.0/12",
        allowed_hosts:[$host],
        tls_cert_file:"/etc/plntir/web/tls.crt",
        tls_key_file:"/etc/plntir/web/tls.key",
        auth_file:"/etc/plntir/web/auth.json",
        status_command:["/opt/plntir/bin/status-v2"],
        action_command:["/usr/bin/sudo","-n","-u","admin","/opt/plntir/bin/plntir-web-action"],
        monitor_root:"/var/lib/plntir/monitor",
        retrieved_root:"/var/lib/plntir/retrieved",
        audit_file:"/var/lib/plntir-web/audit.jsonl",
        managed_home:$home,
        refresh_seconds:10,
        session_minutes:480,
        private_session_minutes:10,
        max_response_bytes:8388608
    }' >"${config_tmp}"
/bin/chown root:"${WEB_GROUP}" "${config_tmp}"
/bin/chmod 0640 "${config_tmp}"
/bin/mv -f "${config_tmp}" /etc/plntir/web-console.json
trap - EXIT

/usr/sbin/visudo -cf /etc/sudoers
/usr/sbin/nft -c -f "${BUNDLE}/config/nftables/nftables.conf"
/usr/bin/install -o root -g root -m 0755 \
    "${BUNDLE}/config/nftables/nftables.conf" /etc/nftables.conf
/usr/sbin/nft -f /etc/nftables.conf
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable plntir-web.service
/usr/bin/systemctl restart plntir-web.service
/usr/bin/systemctl is-active --quiet plntir-web.service
/usr/sbin/runuser -u "${WEB_USER}" -- \
    /opt/plntir/bin/plntir-web check-config --config /etc/plntir/web-console.json
dashboard_ready=0
# The fixed retry count is part of the readiness contract; the value is unused.
# shellcheck disable=SC2034
for readiness_attempt in {1..20}; do
    if /usr/bin/curl --fail --silent --cacert /etc/plntir/web/ca.crt \
        --connect-timeout 1 --max-time 2 "https://${MESH_IP}:8443/" >/dev/null; then
        dashboard_ready=1
        break
    fi
    /bin/sleep 0.25
done
((dashboard_ready == 1)) || {
    printf 'Dashboard did not become HTTPS-ready after service restart.\n' >&2
    exit 74
}

printf 'Plntir Mesh web dashboard installed successfully.\n'
printf 'URL: https://%s:8443/\n' "${MESH_IP}"
printf 'Backup: %s\n' "${BACKUP}"
printf 'No public DNS record or public listener was created.\n'
