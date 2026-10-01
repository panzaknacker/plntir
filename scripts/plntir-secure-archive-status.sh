#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly PLNTIR_CONTROL_NODE_HOST=${PLNTIR_CONTROL_NODE_HOST:-192.0.2.10}
readonly PLNTIR_CONTROL_NODE_USER=${PLNTIR_CONTROL_NODE_USER:-admin}

exec /usr/bin/ssh \
    -T \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${ROOT}/secrets/plntir_control_node_known_hosts" \
    -i "${ROOT}/secrets/plntir_control_node_access.pem" \
    "${PLNTIR_CONTROL_NODE_USER}@${PLNTIR_CONTROL_NODE_HOST}" \
    /opt/plntir/bin/plntir-secure-archive-manage --status
