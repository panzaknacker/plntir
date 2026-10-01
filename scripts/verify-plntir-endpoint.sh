#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Mac.\n' >&2
    exit 1
fi
if [[ $# -ne 3 ]]; then
    printf 'usage: %s AGENT_USER MANAGED_USER LEGACY_SSH_USER\n' "$0" >&2
    exit 64
fi
readonly AGENT_USER=$1
readonly MANAGED_USER=$2
readonly LEGACY_SSH_USER=$3
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_DIR
# shellcheck source=scripts/plntir-dscl-output.sh
source "${SCRIPT_DIR}/plntir-dscl-output.sh"
AGENT_HOME=$(/usr/bin/dscl . -read "/Users/${AGENT_USER}" NFSHomeDirectory | /usr/bin/awk '{print $2}')
readonly AGENT_HOME

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
advisory() {
    local pass_description=$1
    local warning_description=$2
    shift 2
    if "$@" >/dev/null 2>&1; then
        printf 'PASS %s\n' "${pass_description}"
    else
        printf 'WARN %s\n' "${warning_description}" >&2
    fi
}

check 'agent account exists' id "${AGENT_USER}"
check 'managed account exists' id "${MANAGED_USER}"
check 'legacy SSH account exists' id "${LEGACY_SSH_USER}"
check 'agent display name is branded' plntir_dscl_attribute_has_value \
    "/Users/${AGENT_USER}" RealName 'Plntir Endpoint Agent'
check 'recovery administrator display name is branded' plntir_dscl_attribute_has_value \
    "/Users/${LEGACY_SSH_USER}" RealName 'Plntir Recovery Administrator'
check 'agent is standard user' sh -c \
    "! dseditgroup -o checkmember -m '${AGENT_USER}' admin 2>/dev/null | grep -Fq 'yes '"
check 'agent is hidden from the login window' sh -c \
    "dscl . -read '/Users/${AGENT_USER}' IsHidden | grep -Eq 'IsHidden:[[:space:]]+1$'"
check 'agent has no Secure Token' sh -c \
    "sysadminctl -secureTokenStatus '${AGENT_USER}' 2>&1 | grep -Fq 'DISABLED'"
check 'agent has SSH access group' sh -c \
    "dseditgroup -o checkmember -m '${AGENT_USER}' com.apple.access_ssh | grep -Fq 'yes '"
check 'legacy account retains SSH access for rollback' sh -c \
    "dseditgroup -o checkmember -m '${LEGACY_SSH_USER}' com.apple.access_ssh | grep -Fq 'yes '"
check 'agent belongs to export group' sh -c \
    "dseditgroup -o checkmember -m '${AGENT_USER}' plntirarchive | grep -Fq 'yes '"
check 'two restricted forced keys installed' sh -c \
    "[[ \$(grep -Ec '^from=\"[^\"]+\",restrict,command=\"/usr/local/libexec/plntir-(monitor|response)-dispatch\"[[:space:]]' '${AGENT_HOME}/.ssh/authorized_keys') -eq 2 ]]"
check 'sudoers syntax' visudo -cf /etc/sudoers
check 'sshd syntax' sshd -t
check 'SSH passwords disabled' sh -c \
    "sshd -T -C user='${AGENT_USER}',host=localhost,addr=127.0.0.1 | grep -Fxq 'passwordauthentication no'"
check 'SSH forwarding disabled' sh -c \
    "sshd -T -C user='${AGENT_USER}',host=localhost,addr=127.0.0.1 | grep -Fxq 'disableforwarding yes'"
check 'health dispatcher works' sh -c \
    "sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND=health-v1 /usr/local/libexec/plntir-monitor-dispatch | grep -Fq 'remote_login=reachable'"
check 'posture dispatcher works' sh -c \
    "sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND=posture-v1 /usr/local/libexec/plntir-monitor-dispatch | grep -Fq '### SECURITY'"
check 'response status works' sh -c \
    "sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND=response-status-v1 /usr/local/libexec/plntir-response-dispatch | grep -Fq 'remote_login='"
check 'monitor rejects shell' sh -c \
    "! sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND='bash -s --' /usr/local/libexec/plntir-monitor-dispatch"
check 'response rejects shell' sh -c \
    "! sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND='bash -s --' /usr/local/libexec/plntir-response-dispatch"
advisory 'MDM enrolled' 'MDM is not enrolled; enrollment is the next management step' sh -c \
    "profiles status -type enrollment | grep -Fq 'MDM enrollment: Yes'"

exit "${failed}"
