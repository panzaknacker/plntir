#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Mac.\n' >&2
    exit 1
fi
if [[ $# -ne 5 ]]; then
    printf 'usage: %s AGENT_USER BREAKGLASS_USER PLNTIR_CONTROL_NODE_IP ARCHIVE_PUBLIC_KEY BREAKGLASS_PUBLIC_KEY\n' "$0" >&2
    exit 64
fi

readonly AGENT_USER=$1
readonly BREAKGLASS_USER=$2
readonly PLNTIR_CONTROL_NODE_IP=$3
readonly ARCHIVE_PUBLIC_KEY=$4
readonly BREAKGLASS_PUBLIC_KEY=$5
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_DIR
# shellcheck source=scripts/plntir-dscl-output.sh
source "${SCRIPT_DIR}/plntir-dscl-output.sh"
AGENT_HOME=$(/usr/bin/dscl . -read "/Users/${AGENT_USER}" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
BREAKGLASS_HOME=$(/usr/bin/dscl . -read "/Users/${BREAKGLASS_USER}" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')
archive_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${ARCHIVE_PUBLIC_KEY}")
breakglass_blob=$(/usr/bin/awk 'NF && $1 !~ /^#/ {print $2; exit}' "${BREAKGLASS_PUBLIC_KEY}")
readonly AGENT_HOME BREAKGLASS_HOME archive_blob breakglass_blob

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

check 'restricted agent is not an administrator' sh -c \
    "! dseditgroup -o checkmember -m '${AGENT_USER}' admin 2>/dev/null | grep -Fq 'yes '"
check 'agent display name is branded' plntir_dscl_attribute_has_value \
    "/Users/${AGENT_USER}" RealName 'Plntir Endpoint Agent'
check 'break-glass account is an administrator' sh -c \
    "dseditgroup -o checkmember -m '${BREAKGLASS_USER}' admin 2>/dev/null | grep -Fq 'yes '"
check 'recovery administrator display name is branded' plntir_dscl_attribute_has_value \
    "/Users/${BREAKGLASS_USER}" RealName 'Plntir Recovery Administrator'
check 'break-glass account has a Secure Token' sh -c \
    "sysadminctl -secureTokenStatus '${BREAKGLASS_USER}' 2>&1 | grep -Fq ENABLED"
check 'root export helper is protected' sh -c \
    "test \"\$(stat -f '%Su:%Sg:%Lp' /usr/local/libexec/plntir-secure-archive)\" = root:wheel:755"
check 'root export dispatcher is protected' sh -c \
    "test \"\$(stat -f '%Su:%Sg:%Lp' /usr/local/libexec/plntir-secure-archive-dispatch)\" = root:wheel:755"
check 'all-user sudoers file is protected' sh -c \
    "test \"\$(stat -f '%Su:%Sg:%Lp' /etc/sudoers.d/91-plntir-secure-archive)\" = root:wheel:440"
check 'sudoers syntax' visudo -cf /etc/sudoers
check 'archive key is forced and source-restricted' sh -c \
    "grep -F 'from=\"${PLNTIR_CONTROL_NODE_IP}\",restrict,command=\"/usr/local/libexec/plntir-secure-archive-dispatch\"' '${AGENT_HOME}/.ssh/authorized_keys' | grep -Fq '${archive_blob}'"
check 'archive key occurs exactly once' sh -c \
    "test \"\$(grep -Fc '${archive_blob}' '${AGENT_HOME}/.ssh/authorized_keys')\" -eq 1"
check 'break-glass key permits an interactive shell' sh -c \
    "line=\$(grep -F '${breakglass_blob}' '${BREAKGLASS_HOME}/.ssh/authorized_keys'); test \"\$(printf '%s\\n' \"\$line\" | grep -Fc 'from=\"${PLNTIR_CONTROL_NODE_IP}\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc')\" -eq 1 && ! printf '%s\\n' \"\$line\" | grep -Eq 'command=|restrict|no-pty'"
check 'break-glass key occurs exactly once' sh -c \
    "test \"\$(grep -Fc '${breakglass_blob}' '${BREAKGLASS_HOME}/.ssh/authorized_keys')\" -eq 1"
check 'agent sudo permits only fixed export actions' sh -c \
    "sudo -l -U '${AGENT_USER}' | grep -Fq '/usr/local/libexec/plntir-secure-archive plan-v1' && sudo -l -U '${AGENT_USER}' | grep -Fq '/usr/local/libexec/plntir-secure-archive stream-v1'"
check 'agent has no blanket passwordless sudo' sh -c \
    "! sudo -l -U '${AGENT_USER}' | grep -Eq 'NOPASSWD:[[:space:]]*(ALL|/bin/(ba)?sh|/usr/bin/(ba)?sh)'"
check 'archive dispatcher rejects arbitrary commands' sh -c \
    "! sudo -u '${AGENT_USER}' env SSH_ORIGINAL_COMMAND='uname -a' /usr/local/libexec/plntir-secure-archive-dispatch"
check 'sudo rejects extra export arguments' sh -c \
    "! sudo -u '${AGENT_USER}' sudo -n /usr/local/libexec/plntir-secure-archive plan-v1 extra"
exit "${failed}"
