#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}
readonly REMOTE_NAME=${PLNTIR_GIT_REMOTE_NAME:-control-node}
readonly REMOTE_PATH=/var/lib/plntir/git/plntir-control-plane.git
readonly IDENTITY=${ROOT}/secrets/plntir_control_node_access.pem
readonly HOST_KEYS=${ROOT}/secrets/plntir_control_node_known_hosts

[[ ${CONTROL_NODE_HOST} =~ ^[A-Za-z0-9.:-]+$ ]] || exit 64
[[ ${CONTROL_NODE_USER} =~ ^[A-Za-z0-9._-]+$ ]] || exit 64
[[ ${REMOTE_NAME} =~ ^[A-Za-z0-9._-]+$ && ! ${REMOTE_NAME} == -* ]] || exit 64
for path in "${IDENTITY}" "${HOST_KEYS}"; do
    [[ -f ${path} && ! -L ${path} ]] || {
        printf 'Missing or unsafe SSH trust file: %s\n' "${path}" >&2
        exit 66
    }
done

expected_url=${CONTROL_NODE_USER}@${CONTROL_NODE_HOST}:${REMOTE_PATH}
actual_url=$(/usr/bin/git -C "${ROOT}" remote get-url --push "${REMOTE_NAME}") || {
    printf 'Missing Git remote: %s\n' "${REMOTE_NAME}" >&2
    exit 66
}
[[ ${actual_url} == "${expected_url}" ]] || {
    printf 'Refusing unexpected Git push URL: %s\n' "${actual_url}" >&2
    exit 77
}
if ! /usr/bin/git -C "${ROOT}" diff --quiet ||
    ! /usr/bin/git -C "${ROOT}" diff --cached --quiet; then
    printf 'Commit tracked changes before creating the off-host Git copy.\n' >&2
    exit 65
fi
/usr/bin/git -C "${ROOT}" rev-parse --verify HEAD >/dev/null

printf -v ssh_command \
    '/usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -i %q' \
    "${HOST_KEYS}" "${IDENTITY}"
GIT_SSH_COMMAND=${ssh_command} GIT_SSH_VARIANT=ssh \
    /usr/bin/git -C "${ROOT}" push "${REMOTE_NAME}" HEAD:refs/heads/main

printf 'Pushed reviewed source history to %s.\n' "${REMOTE_NAME}"
