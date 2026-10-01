#!/bin/bash
set -u

if [[ $(/usr/bin/uname -s) != Darwin ]]; then
    printf 'This preflight must run on macOS.\n' >&2
    exit 69
fi
if [[ ${EUID} -ne 0 ]]; then
    printf 'Run with sudo from an authenticated administrator session.\n' >&2
    exit 1
fi

section() {
    printf '\n### %s\n' "$1"
}
run_optional() {
    "$@" 2>&1 || true
}

section SYSTEM
/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ
/usr/bin/sw_vers
/usr/bin/uname -m
/usr/bin/uptime
/bin/df -h /

section ENROLLMENT
run_optional /usr/bin/profiles status -type enrollment
run_optional /usr/bin/profiles status -type bootstraptoken

section PLATFORM_SECURITY
run_optional /usr/bin/csrutil status
run_optional /usr/sbin/spctl --status
run_optional /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
run_optional /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

section REMOTE_ACCESS
run_optional /usr/sbin/systemsetup -getremotelogin
run_optional /usr/bin/dscl . -read /Groups/com.apple.access_ssh GroupMembership

section LOCAL_ACCOUNTS
run_optional /usr/bin/dscl . -read /Groups/admin GroupMembership
while read -r account uid; do
    [[ ${uid} =~ ^[0-9]+$ && ${uid} -ge 501 ]] || continue
    printf '%s uid=%s ' "${account}" "${uid}"
    run_optional /usr/sbin/sysadminctl -secureTokenStatus "${account}"
done < <(/usr/bin/dscl . -list /Users UniqueID)

section BACKUP
run_optional /usr/bin/tmutil latestbackup
run_optional /usr/bin/tmutil listlocalsnapshots /

section MESH
run_optional /usr/local/bin/warp-cli status
run_optional /sbin/ifconfig

section RECENT_UPDATES
run_optional /usr/sbin/softwareupdate --history

printf '\nPreflight is read-only. Review its output before provisioning.\n'
