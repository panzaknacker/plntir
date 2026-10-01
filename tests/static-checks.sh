#!/usr/bin/env bash
set -Eeuo pipefail

if ! plntir_rg_bin=$(command -v rg); then
    printf 'Missing required tool: rg (ripgrep) must be available in PATH.\n' >&2
    exit 1
fi
readonly plntir_rg_bin

cd "$(dirname "$0")/.."

bash_files=(
    scripts/*.sh
    scripts/run-plntir-endpoint-update.sh.in
    scripts/run-plntir-access-upgrade.sh.in
    scripts/run-plntir-cloudflare-ca-trust.sh.in
    scripts/run-plntir-platform-update.sh.in
    scripts/install-plntir-platform-update.sh.in
    control-node/bin/*
    control-node/lib/*.sh
    client/internal/collector/plntir-status-v2.sh
    mac/libexec/plntir-monitor-dispatch
    mac/libexec/plntir-response-dispatch.in
    mac/libexec/plntir-secure-archive-dispatch
    mac/libexec/plntir-secure-archive
    mac/libexec/plntir-integrity-check
)
sh_files=(
    mac/libexec/plntir-health-collector
    mac/libexec/plntir-response-status
    mac/libexec/plntir-security-collector
    mac/libexec/plntir-retrieval-export
)

/bin/bash -n "${bash_files[@]}" "${sh_files[@]}"
for path in "${sh_files[@]}"; do
    /bin/sh -n "${path}"
done

/usr/bin/python3 -c \
    'import ast, pathlib; [ast.parse(pathlib.Path(p).read_text()) for p in __import__("sys").argv[1:]]' \
    mac/libexec/plntir-retrieval-export.py \
    mac/libexec/plntir-retrieval-export.py.in

for path in config/*.json; do
    /usr/bin/jq -e . "${path}" >/dev/null
done

if "${plntir_rg_bin}" -n \
    'NOPASSWD:[[:space:]]*(ALL|/bin/(ba)?sh|/usr/bin/(ba)?sh)' \
    config control-node mac scripts; then
    printf 'Blanket passwordless sudo rule found.\n' >&2
    exit 1
fi
if "${plntir_rg_bin}" -n \
    'command="[^"]*(/bin/(ba)?sh|/usr/bin/(ba)?sh)' \
    config control-node mac scripts; then
    printf 'Forced key grants a shell.\n' >&2
    exit 1
fi
/usr/bin/grep -Fxq 'Match all' mac/sshd/90-plntir-endpoint.conf.in
/usr/bin/grep -Fq \
    'PACKAGE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)' \
    scripts/install-plntir-endpoint-update.sh
/usr/bin/grep -Fxq 'MAC_TRANSPORT=dispatch' \
    control-node/config/managed-endpoint.conf.example
/usr/bin/grep -Fq 'schema_version: 2' \
    client/internal/collector/plntir-status-v2.sh
/usr/bin/grep -Fq 'timers: {control_node: $control_node_timer' \
    client/internal/collector/plntir-status-v2.sh
/usr/bin/grep -Fq 'SSH_ORIGINAL_COMMAND-} != status-v2' \
    control-node/bin/plntir-observer-dispatch
/usr/bin/grep -Fq 'command="/usr/local/libexec/plntir-secure-archive-dispatch"' \
    scripts/provision-plntir-access-upgrade.sh
/usr/bin/grep -Fq '/usr/local/libexec/plntir-secure-archive plan-v1' \
    mac/sudoers/91-plntir-secure-archive.in
/usr/bin/grep -Fq -- '-d -r trustRoot -p ssl -k "${SYSTEM_KEYCHAIN}" "${SOURCE_CERT}"' \
    scripts/install-plntir-cloudflare-ca-trust.sh
/usr/bin/grep -Fq 'Certificate fingerprint mismatch; refusing to add trust.' \
    scripts/install-plntir-cloudflare-ca-trust.sh
/usr/bin/grep -Fq 'readonly EXPECTED_CHECKSUM=@CHECKSUM@' \
    scripts/run-plntir-cloudflare-ca-trust.sh.in
/usr/bin/grep -Fq 'readonly EXPECTED_CHECKSUM=@CHECKSUM@' \
    scripts/run-plntir-platform-update.sh.in
/usr/bin/grep -Fq \
    '[[ $archive =~ ^/Users/Shared/[.]plntir/archive/retrievals/' \
    control-node/bin/plntir-endpoint-retrieve
/usr/bin/grep -Fq 'readonly PLAN_CACHE_MAX_AGE_SECONDS=$((7 * 24 * 60 * 60))' \
    control-node/bin/plntir-secure-archive-manage
/usr/bin/grep -Fq 'if reuse_recent_storage_block; then' \
    control-node/bin/plntir-secure-archive-manage
/usr/bin/grep -Fq 'exec /usr/bin/nice -n 10' \
    mac/libexec/plntir-monitor-dispatch
/usr/bin/grep -Fq 'exec /usr/bin/nice -n 10' \
    mac/libexec/plntir-secure-archive-dispatch
/usr/bin/grep -Fq 'readonly ENDPOINT_CHECKSUM=@ENDPOINT_CHECKSUM@' \
    scripts/install-plntir-platform-update.sh.in
/usr/bin/grep -Fq '/usr/bin/ssh-keygen -Y verify' \
    scripts/run-plntir-platform-update.sh.in
/usr/bin/grep -Fq 'stage=integrity-alert-only' \
    scripts/install-plntir-platform-update.sh.in
/usr/bin/grep -Fq 'integrity_mode=alert-only' \
    mac/libexec/plntir-integrity-check
if "${plntir_rg_bin}" -n 'fdesetup|filevault=' \
    mac/libexec/plntir-health-collector \
    mac/libexec/plntir-response-status \
    mac/libexec/plntir-security-collector \
    control-node/bin/plntir-endpoint-check \
    scripts/plntir-endpoint-preflight.sh \
    scripts/verify-plntir-endpoint.sh; then
    printf 'Disk-encryption collection remains in the active status path.\n' >&2
    exit 1
fi
if /usr/bin/grep -Fq 'FileVault' client/internal/ui/render.go; then
    printf 'Dashboard still renders an out-of-scope disk-encryption policy.\n' >&2
    exit 1
fi
if /usr/bin/grep -Fq 'all-users-plan-v1' scripts/install-plntir-access-upgrade.sh; then
    printf 'Access installer still scans /Users without a separate operator action.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'Type exactly "EXPORT /Users" to approve:' \
    scripts/start-plntir-secure-archive.sh
/usr/bin/grep -Fq 'disable --now plntir-secure-archive-readiness.timer' \
    scripts/provision-plntir-control-node.sh
if /usr/bin/grep -Fq 'WantedBy=timers.target' \
    control-node/systemd/plntir-secure-archive-readiness.timer; then
    printf 'All-user readiness timer is still enableable as a default timer.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'No background private-data reader is started.' \
    scripts/connect-plntir-root.sh
/usr/bin/grep -Fq -- '--apply-staged-update' scripts/connect-plntir-root.sh
/usr/bin/grep -Fq 'remote_command=(/usr/bin/sudo "${STAGED_UPDATE}")' \
    scripts/connect-plntir-root.sh
/usr/bin/grep -Fxq 'cd /' scripts/install-plntir-access-upgrade.sh
/usr/bin/grep -Fxq 'cd /' scripts/install-plntir-endpoint-update.sh
if /usr/bin/grep -Fq 'previous_state=$(/bin/sed' \
    mac/libexec/plntir-integrity-check; then
    printf 'Integrity checker uses a sed path absent on current macOS.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq '<integer>300</integer>' \
    mac/launchd/com.plntir.endpoint-integrity.plist
/usr/bin/grep -Fq 'If-None-Match: *' \
    control-node/bin/plntir-control-plane-backup
/usr/bin/grep -Fq 'plntir-control-plane-backup --upload' \
    control-node/systemd/plntir-control-plane-backup.service
/usr/bin/grep -Fq '/Users/Shared/PlntirSecureArchive' \
    scripts/install-plntir-platform-update.sh.in
/usr/bin/grep -Fq '/usr/bin/chflags hidden "${legacy_directory}"' \
    scripts/install-plntir-platform-update.sh.in
/usr/bin/grep -Fq 'if [[ -e ${target} ]]; then' \
    scripts/activate-plntir-secure-access.sh
for expected_policy in \
    "allowtcpforwarding local" \
    "permitopen 100.101.0.2:22 127.0.0.1:1337" \
    "disableforwarding yes"; do
    /usr/bin/grep -Fq "/usr/bin/grep -Fx '${expected_policy}' >/dev/null" \
        scripts/activate-plntir-secure-access.sh
done
[[ ! -e config/sshd/99-plntir-control-node.conf ]]
/usr/bin/grep -Fq \
    'fleetdm/fleet:v4.89.2@sha256:862604e5d2ae67bc7a2476645e11a0af0b153f4be496dcf69ca0dbc1cd56a71a' \
    mdm/fleet/compose.yaml
/usr/bin/grep -Fq '${FLEET_ADMIN_BIND_ADDRESS:?set FLEET_ADMIN_BIND_ADDRESS}:1337:8080' \
    mdm/fleet/compose.yaml
/usr/bin/grep -Fq '${FLEET_DEVICE_BIND_ADDRESS:?set FLEET_DEVICE_BIND_ADDRESS}:1338:8080' \
    mdm/fleet/compose.yaml
for bridge_name in plntir-mdm-be plntir-mdm-dev plntir-mdm-eg; do
    /usr/bin/grep -Fq "com.docker.network.bridge.name: ${bridge_name}" \
        mdm/fleet/compose.yaml
done
/usr/bin/grep -Fq 'iifname "{{ interface }}" oifname "{{ interface }}" accept' \
    infra/ansible/roles/baseline/templates/plntir-filter.nft.j2
if /usr/bin/grep -Fq 'iifname "br-*" accept' \
    infra/ansible/roles/baseline/templates/plntir-filter.nft.j2; then
    printf 'Ansible firewall grants every Docker bridge forwarding.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'golang:1.24.7-alpine3.22@sha256:8aebdc2031bd790173104c00a69a5652658f9cfe14ae853a0264f2909d67fba7' \
    mdm/fleet/ingress-proxy/Dockerfile
/usr/bin/grep -Fq 'No public Tunnel, DNS record, APNs credential, enrollment, or disk-encryption change was made.' \
    scripts/install-plntir-device-management-base.sh
/usr/bin/grep -Fq 'AWS-StartPortForwardingSessionToRemoteHost' \
    scripts/connect-plntir-device-management.sh
if "${plntir_rg_bin}" -n \
    '(fleet\.plntir\.example|ops\.plntir\.example|/api/(v1/)?osquery/[.][*]|/api/fleet/orbit/[.][*])' \
    mdm/fleet/cloudflared.example.yml; then
    printf 'Broad or obsolete Fleet public ingress remains.\n' >&2
    exit 1
fi

old_brand_hits=$("${plntir_rg_bin}" -n -i \
    --glob '!client/internal/status/status.go' \
    --glob '!client/internal/status/status_test.go' \
    --glob '!static-checks.sh' \
    --glob '!package-build-checks.sh' \
    --glob '!install-plntir-control-node-migration.sh' \
    --glob '!generated/**' \
    'watchdog|mac-control-plane|mac control plane|macctl|macwatchdog|maccontrol' \
    README.md Makefile client config control-node mac mdm scripts tests || true)
if [[ -n ${old_brand_hits} ]]; then
    printf '%s\n' "${old_brand_hits}" >&2
    printf 'Legacy product branding remains outside the explicit status-v1 compatibility parser.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'readonly LEGACY_STATE=/var/lib/mac-control-plane' \
    scripts/install-plntir-control-node-migration.sh
/usr/bin/grep -Fq 'mac-watchdog.timer' \
    scripts/install-plntir-control-node-migration.sh
/usr/bin/grep -Fq -- '--copy-legacy-retrieved' \
    scripts/install-plntir-control-node-migration.sh
/usr/bin/grep -Fq '/usr/bin/diff -qr "${LEGACY_STATE}/retrieved" "${LEGACY_RETRIEVED_TARGET}"' \
    scripts/install-plntir-control-node-migration.sh
/usr/bin/grep -Fq '/bin/cat "${RECIPIENT_SOURCE}" |' \
    scripts/activate-plntir-secure-access.sh
/usr/bin/grep -Fq \
    'readonly SSHD_OBSERVER=/etc/ssh/sshd_config.d/10-plntir-observer.conf' \
    scripts/provision-plntir-control-node.sh
[[ ! -e control-node/sshd/zz-plntir-observer.conf ]]
if "${plntir_rg_bin}" -n -F "grep -Fxq 'RealName: Plntir" \
    scripts/verify-plntir-endpoint.sh \
    scripts/verify-plntir-access-upgrade.sh; then
    printf 'Verifier still assumes one-line dscl RealName output.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'plntir_dscl_attribute_has_value' \
    scripts/verify-plntir-endpoint.sh
/usr/bin/grep -Fq 'plntir_dscl_attribute_has_value' \
    scripts/verify-plntir-access-upgrade.sh

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose \
        --env-file mdm/fleet/fleet.env.example \
        -f mdm/fleet/compose.yaml \
        config --quiet
else
    printf 'SKIP docker compose validation (not installed)\n'
fi

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${bash_files[@]}" "${sh_files[@]}"
else
    printf 'SKIP shellcheck (not installed locally)\n'
fi

printf 'Static checks passed.\n'
