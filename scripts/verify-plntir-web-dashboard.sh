#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi

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

# check() invokes this callback through "$@".
# shellcheck disable=SC2329
firewall_web_accept_is_unique() {
    local count
    count=$(/usr/sbin/nft list chain inet host_filter input |
        /usr/bin/grep -Ec 'tcp dport 8443 accept' || true)
    [[ ${count} -eq 1 ]]
}

# check() invokes this callback through "$@".
# shellcheck disable=SC2329
unauthenticated_api_is_denied() {
    local code
    code=$(/usr/bin/curl --silent --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/plntir/web/ca.crt "https://${mesh_ip}:8443/api/status")
    [[ ${code} == 401 ]]
}

mesh_ip=$(/usr/sbin/ip -4 -o address show dev CloudflareWARP |
    /usr/bin/awk 'NR == 1 {sub(/\/.*/, "", $4); print $4}')
check 'web service account exists' /usr/bin/id plntirweb
check 'web service account is locked' /bin/bash -c \
    "/usr/bin/passwd -S plntirweb | /usr/bin/awk '{exit !(\$2 == \"L\")}'"
check 'web service has no login shell' /bin/bash -c \
    "/usr/bin/getent passwd plntirweb | /usr/bin/awk -F: '{exit !(\$7 == \"/usr/sbin/nologin\")}'"
check 'web service belongs to control group' /bin/bash -c \
    "/usr/bin/id -nG plntirweb | /usr/bin/tr ' ' '\\n' | /usr/bin/grep -Fxq plntircontrol"
check 'web config permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /etc/plntir/web-console.json)\" = root:plntirweb:640"
check 'web TLS key permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /etc/plntir/web/tls.key)\" = root:plntirweb:640"
check 'web auth permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /etc/plntir/web/auth.json)\" = root:plntirweb:640"
check 'web audit permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /var/lib/plntir-web/audit.jsonl)\" = plntirweb:plntirweb:600"
check 'status collector permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /opt/plntir/bin/status-v2)\" = root:plntircontrol:750"
check 'status collector uses strict enabled states' /usr/bin/grep -Fq \
    'enabled|enabled-runtime' /opt/plntir/bin/status-v2
check 'control backup helper permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /opt/plntir/bin/plntir-control-plane-backup)\" = root:plntircontrol:750"
check 'control backup includes dashboard state' /usr/bin/grep -Eq \
    '^[[:space:]]+var/lib/plntir-web$' /opt/plntir/bin/plntir-control-plane-backup
check 'endpoint retrieval helper permissions' /bin/bash -c \
    "test \"\$(/usr/bin/stat -Lc '%U:%G:%a' /opt/plntir/bin/plntir-endpoint-retrieve)\" = root:root:755"
check 'endpoint retrieval supports dashboard actions' /bin/bash -c \
    "/usr/bin/grep -Fq -- '--safari-history)' /opt/plntir/bin/plntir-endpoint-retrieve && /usr/bin/grep -Fq 'mode=list-b64' /opt/plntir/bin/plntir-endpoint-retrieve"
check 'sudoers syntax' /usr/sbin/visudo -cf /etc/sudoers
check 'web sudo has no blanket command' /bin/bash -c \
    "! /usr/bin/sudo -l -U plntirweb | /usr/bin/grep -Eq 'NOPASSWD:[[:space:]]*(ALL|/bin/(ba)?sh)'"
check 'web dispatcher rejects arbitrary action' /bin/bash -c \
    "! /usr/bin/sudo -n -u admin /opt/plntir/bin/plntir-web-action shell"
check 'web config parses' /usr/sbin/runuser -u plntirweb -- \
    /opt/plntir/bin/plntir-web check-config --config /etc/plntir/web-console.json
check 'web service enabled' /usr/bin/systemctl is-enabled --quiet plntir-web.service
check 'web service active' /usr/bin/systemctl is-active --quiet plntir-web.service
check 'web listener uses exact Mesh address' /bin/bash -c \
    "/usr/bin/ss -H -lnt | /usr/bin/awk '{print \$4}' | /usr/bin/grep -Fxq '${mesh_ip}:8443'"
check 'no wildcard web listener exists' /bin/bash -c \
    "! /usr/bin/ss -H -lnt | /usr/bin/awk '{print \$4}' | /usr/bin/grep -Eq '^([*]|0[.]0[.]0[.]0|\\[::\\]):8443$'"
check 'firewall allows web only on WARP interface' /bin/bash -c \
    "/usr/sbin/nft list chain inet host_filter input | /usr/bin/grep -Fq 'iifname \"CloudflareWARP\" tcp dport 8443 accept'"
check 'firewall has no public web accept' firewall_web_accept_is_unique
check 'TLS certificate matches Mesh IP' /usr/bin/openssl verify \
    -CAfile /etc/plntir/web/ca.crt -verify_ip "${mesh_ip}" /etc/plntir/web/tls.crt
check 'HTTPS dashboard responds on Mesh IP' /usr/bin/curl --fail --silent \
    --cacert /etc/plntir/web/ca.crt --connect-timeout 5 "https://${mesh_ip}:8443/"
check 'unauthenticated API is denied' unauthenticated_api_is_denied

exit "${failed}"
