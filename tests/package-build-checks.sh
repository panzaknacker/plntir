#!/usr/bin/env bash
set -Eeuo pipefail

if ! plntir_rg_bin=$(command -v rg); then
    printf 'Missing required tool: rg (ripgrep) must be available in PATH.\n' >&2
    exit 1
fi
readonly plntir_rg_bin

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT

for role in monitor response archive recovery release; do
    /usr/bin/ssh-keygen -q -t ed25519 -N '' \
        -C "plntir-test-${role}" \
        -f "${workdir}/${role}_ed25519"
done

output=${workdir}/Plntir-Platform-Update
if ! "${ROOT}/scripts/build-plntir-platform-update.sh" \
    "${output}" \
    testuser \
    bootstrapadmin \
    100.101.0.5 \
    "${workdir}/monitor_ed25519.pub" \
    "${workdir}/response_ed25519.pub" \
    "${workdir}/archive_ed25519.pub" \
    "${workdir}/recovery_ed25519.pub" \
    "${workdir}/release_ed25519" \
    >"${workdir}/build.log" 2>&1; then
    /bin/cat "${workdir}/build.log" >&2
    exit 1
fi

(
    cd "${output}"
    /usr/bin/sha256sum -c plntir-platform-update.sha256
    /usr/bin/ssh-keygen -Y verify \
        -f plntir-release-allowed-signers \
        -I plntir-release \
        -n plntir-endpoint-recovery \
        -s plntir-platform-update.tar.gz.sig \
        <plntir-platform-update.tar.gz >/dev/null
    /usr/bin/grep -Fxq \
        'sudo /Users/Shared/.plntir/inbox/platform-update/run.sh' RUN_ME.txt
    /usr/bin/grep -Fq '/usr/bin/ssh-keygen -Y verify' run.sh
    /bin/bash -n run.sh
)

/bin/cp "${output}/plntir-platform-update.tar.gz" "${workdir}/tampered.tar.gz"
/usr/bin/printf 'tamper\n' >>"${workdir}/tampered.tar.gz"
if /usr/bin/ssh-keygen -Y verify \
    -f "${output}/plntir-release-allowed-signers" \
    -I plntir-release \
    -n plntir-endpoint-recovery \
    -s "${output}/plntir-platform-update.tar.gz.sig" \
    <"${workdir}/tampered.tar.gz" >/dev/null 2>&1; then
    printf 'Tampered recovery archive unexpectedly passed signature verification.\n' >&2
    exit 1
fi

extract=${workdir}/extract
/usr/bin/install -d -m 0700 "${extract}"
/usr/bin/tar -xzf "${output}/plntir-platform-update.tar.gz" -C "${extract}"
package=${extract}/plntir-platform-update
/bin/bash -n "${package}/install.sh"
/bin/bash -n "${package}/mac/libexec/plntir-integrity-check"
/bin/bash -n "${package}/scripts/install-plntir-integrity-monitor.sh"
/usr/bin/grep -Fq 'integrity-alert-only' "${package}/install.sh"

endpoint_expected=$(/bin/sed -n \
    's/^readonly ENDPOINT_CHECKSUM=//p' "${package}/install.sh")
access_expected=$(/bin/sed -n \
    's/^readonly ACCESS_CHECKSUM=//p' "${package}/install.sh")
endpoint_actual=$(/usr/bin/sha256sum \
    "${package}/payloads/plntir-endpoint-update.tar.gz" | /usr/bin/awk '{print $1}')
access_actual=$(/usr/bin/sha256sum \
    "${package}/payloads/plntir-access-upgrade.tar.gz" | /usr/bin/awk '{print $1}')
[[ ${endpoint_expected} == "${endpoint_actual}" ]]
[[ ${access_expected} == "${access_actual}" ]]

for role in endpoint access; do
    /usr/bin/install -d -m 0700 "${workdir}/${role}"
done
/usr/bin/tar -xzf "${package}/payloads/plntir-endpoint-update.tar.gz" \
    -C "${workdir}/endpoint"
/usr/bin/tar -xzf "${package}/payloads/plntir-access-upgrade.tar.gz" \
    -C "${workdir}/access"

if /usr/bin/grep -Fq 'all-users-plan-v1' \
    "${workdir}/access/plntir-access-upgrade/install.sh"; then
    printf 'Generated access installer unexpectedly scans /Users.\n' >&2
    exit 1
fi
/usr/bin/grep -Fq 'private-data access stays on-demand' \
    "${workdir}/access/plntir-access-upgrade/install.sh"

for helper in \
    "${workdir}/endpoint/plntir-endpoint-update/scripts/plntir-dscl-output.sh" \
    "${workdir}/access/plntir-access-upgrade/scripts/plntir-dscl-output.sh"; do
    [[ -f ${helper} && ! -L ${helper} ]]
done

if "${plntir_rg_bin}" -n -i \
    'watchdog|mac-control-plane|mac control plane|macctl|macwatchdog|maccontrol' \
    "${extract}" "${workdir}/endpoint" "${workdir}/access"; then
    printf 'Legacy product branding found in generated package.\n' >&2
    exit 1
fi

printf 'Package build checks passed.\n'
