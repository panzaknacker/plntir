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

[[ ${PLNTIR_CONTROL_NODE_HOST} =~ ^[A-Za-z0-9.:-]+$ ]] || exit 64
[[ ${PLNTIR_CONTROL_NODE_USER} =~ ^[A-Za-z0-9._-]+$ ]] || exit 64
[[ ${MAC_TARGET} =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.:-]+$ ]] || exit 64
for path in "${PLNTIR_CONTROL_NODE_KEY}" "${PLNTIR_CONTROL_NODE_HOST_KEYS}" "${MAC_KEY}" "${MAC_HOST_KEYS}"; do
    [[ -f ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe SSH file: %s\n' "${path}" >&2
        exit 66
    }
done

printf -v proxy_command \
    '/usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -i %q -W %%h:%%p %q@%q' \
    "${PLNTIR_CONTROL_NODE_HOST_KEYS}" "${PLNTIR_CONTROL_NODE_KEY}" "${PLNTIR_CONTROL_NODE_USER}" "${PLNTIR_CONTROL_NODE_HOST}"

tty_option=(-t)
if [[ $# -gt 0 ]]; then
    tty_option=(-T)
fi
exec /usr/bin/ssh \
    "${tty_option[@]}" \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o PasswordAuthentication=no \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${MAC_HOST_KEYS}" \
    -o ProxyCommand="${proxy_command}" \
    -i "${MAC_KEY}" \
    "${MAC_TARGET}" \
    "$@"
