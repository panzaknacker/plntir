#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly PLNTIR_CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly PLNTIR_CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}
readonly MAC_TARGET=${MAC_TARGET:-bootstrapadmin@100.101.0.2}
readonly PLNTIR_CONTROL_NODE_KEY=${ROOT}/secrets/plntir_control_node_access.pem
readonly PLNTIR_CONTROL_NODE_HOST_KEYS=${ROOT}/secrets/plntir_control_node_known_hosts
readonly MAC_KEY=${ROOT}/secrets/plntir_recovery_ed25519
readonly MAC_HOST_KEYS=${ROOT}/secrets/plntir_endpoint_known_hosts
readonly STAGED_UPDATE=/Users/Shared/.plntir/inbox/platform-update/run.sh

[[ ${PLNTIR_CONTROL_NODE_HOST} =~ ^[A-Za-z0-9.:-]+$ ]] || exit 64
[[ ${PLNTIR_CONTROL_NODE_USER} =~ ^[A-Za-z0-9._-]+$ ]] || exit 64
[[ ${MAC_TARGET} =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.:-]+$ ]] || exit 64
for path in "${PLNTIR_CONTROL_NODE_KEY}" "${PLNTIR_CONTROL_NODE_HOST_KEYS}" \
    "${MAC_KEY}" "${MAC_HOST_KEYS}"; do
    [[ -f ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe SSH file: %s\n' "${path}" >&2
        exit 66
    }
done

case $# in
0)
    printf 'Opening an on-demand Plntir recovery session. No background private-data reader is started.\n'
    printf 'Enter the bootstrapadmin Mac password when sudo prompts in this SSH terminal.\n'
    printf 'Direct SSH login as root remains disabled. Exit the root shell with Ctrl-D.\n'
    remote_command=(/usr/bin/sudo -i)
    ;;
1)
    if [[ $1 != --apply-staged-update ]]; then
        printf 'usage: %s [--apply-staged-update]\n' "$0" >&2
        exit 64
    fi
    printf 'Starting the one-shot signed Plntir update. No root shell will remain open.\n'
    printf 'Enter the bootstrapadmin Mac password when sudo prompts in this SSH terminal.\n'
    remote_command=(/usr/bin/sudo "${STAGED_UPDATE}")
    ;;
*)
    printf 'usage: %s [--apply-staged-update]\n' "$0" >&2
    exit 64
    ;;
esac

printf -v proxy_command \
    '/usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -i %q -W %%h:%%p %q@%q' \
    "${PLNTIR_CONTROL_NODE_HOST_KEYS}" "${PLNTIR_CONTROL_NODE_KEY}" \
    "${PLNTIR_CONTROL_NODE_USER}" "${PLNTIR_CONTROL_NODE_HOST}"

exec /usr/bin/ssh \
    -tt \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o PasswordAuthentication=no \
    -o PermitLocalCommand=no \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=4 \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${MAC_HOST_KEYS}" \
    -o ProxyCommand="${proxy_command}" \
    -i "${MAC_KEY}" \
    "${MAC_TARGET}" \
    "${remote_command[@]}"
