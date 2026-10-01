#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly PLNTIR_CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly PLNTIR_CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}
readonly PLNTIR_CONTROL_NODE_KEY=${ROOT}/secrets/plntir_control_node_access.pem
readonly PLNTIR_CONTROL_NODE_HOST_KEYS=${ROOT}/secrets/plntir_control_node_known_hosts

if [[ ! -t 0 || ! -t 1 ]]; then
    printf 'Refusing a non-interactive all-user export request.\n' >&2
    exit 77
fi
printf 'This one-time operation reads /Users, streams it encrypted, and stops when complete.\n'
printf 'Type exactly "EXPORT /Users" to approve: '
IFS= read -r confirmation
if [[ ${confirmation} != 'EXPORT /Users' ]]; then
    printf 'All-user export cancelled; no readiness scan was started.\n'
    exit 0
fi

ssh_command=(
    /usr/bin/ssh
    -T
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${PLNTIR_CONTROL_NODE_HOST_KEYS}"
    -i "${PLNTIR_CONTROL_NODE_KEY}"
    "${PLNTIR_CONTROL_NODE_USER}@${PLNTIR_CONTROL_NODE_HOST}"
)

status=$("${ssh_command[@]}" /opt/plntir/bin/plntir-secure-archive-manage --check)
state=$(printf '%s\n' "${status}" | /usr/bin/jq -r '.state')
if [[ ${state} != ready ]]; then
    printf '%s\n' "${status}" | /usr/bin/jq . >&2
    printf 'All-user export was not started because readiness is %s.\n' "${state}" >&2
    exit 75
fi

"${ssh_command[@]}" sudo -n /usr/bin/systemctl start --no-block plntir-secure-archive.service
printf 'Encrypted all-user export started on the Plntir Control Node.\n'
printf 'The scheduled readiness timer remains disabled.\n'
printf 'Status: ./scripts/plntir-secure-archive-status.sh\n'
