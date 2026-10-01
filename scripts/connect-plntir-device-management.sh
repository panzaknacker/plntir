#!/usr/bin/env bash
set -Eeuo pipefail

readonly PLNTIR_AWS_PROFILE=${PLNTIR_AWS_PROFILE:-plntir-owner}
readonly PLNTIR_AWS_REGION=${PLNTIR_AWS_REGION:-eu-central-1}
readonly PLNTIR_RELAY_INSTANCE_ID=${PLNTIR_RELAY_INSTANCE_ID:-}
readonly PLNTIR_MDM_PRIVATE_IP=${PLNTIR_MDM_PRIVATE_IP:-}
readonly PLNTIR_LOCAL_FLEET_PORT=${PLNTIR_LOCAL_FLEET_PORT:-1337}

valid_ipv4() {
    local value=$1
    local first second third fourth
    [[ ${value} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r first second third fourth <<<"${value}"
    for octet in "${first}" "${second}" "${third}" "${fourth}"; do
        ((10#${octet} <= 255)) || return 1
    done
}

[[ ${PLNTIR_AWS_PROFILE} =~ ^[A-Za-z0-9._-]{1,64}$ ]] || exit 64
[[ ${PLNTIR_AWS_REGION} =~ ^[a-z]{2}-[a-z]+-[0-9]$ ]] || exit 64
[[ ${PLNTIR_RELAY_INSTANCE_ID} =~ ^i-[0-9a-f]{17}$ ]] || {
    printf 'Set PLNTIR_RELAY_INSTANCE_ID to the exact plntir-relay-01 EC2 instance ID.\n' >&2
    exit 64
}
valid_ipv4 "${PLNTIR_MDM_PRIVATE_IP}" || {
    printf 'Set PLNTIR_MDM_PRIVATE_IP to plntir-mdm-01 private IPv4.\n' >&2
    exit 64
}
[[ ${PLNTIR_LOCAL_FLEET_PORT} =~ ^[0-9]{4,5}$ ]] &&
    ((PLNTIR_LOCAL_FLEET_PORT >= 1024 && PLNTIR_LOCAL_FLEET_PORT <= 65535)) || exit 64

AWS_BIN=$(command -v aws) || {
    printf 'AWS CLI v2 is required.\n' >&2
    exit 69
}
JQ_BIN=$(command -v jq) || {
    printf 'jq is required.\n' >&2
    exit 69
}
readonly AWS_BIN JQ_BIN
"${AWS_BIN}" sts get-caller-identity \
    --profile "${PLNTIR_AWS_PROFILE}" \
    --region "${PLNTIR_AWS_REGION}" >/dev/null || {
    printf 'No active AWS-FIDO owner session. Run aws login for profile %s first.\n' \
        "${PLNTIR_AWS_PROFILE}" >&2
    exit 77
}

# These variables belong to jq, not the shell.
# shellcheck disable=SC2016
parameters=$("${JQ_BIN}" -cn \
    --arg host "${PLNTIR_MDM_PRIVATE_IP}" \
    --arg remote_port '1337' \
    --arg local_port "${PLNTIR_LOCAL_FLEET_PORT}" \
    '{host:[$host],portNumber:[$remote_port],localPortNumber:[$local_port]}')
readonly parameters

printf 'Fleet bootstrap/recovery UI: http://127.0.0.1:%s\n' "${PLNTIR_LOCAL_FLEET_PORT}"
printf 'This SSM port-only session traverses plntir-relay-01; Ctrl-C closes it.\n'
exec /usr/bin/env AWS_PAGER= "${AWS_BIN}" ssm start-session \
    --profile "${PLNTIR_AWS_PROFILE}" \
    --region "${PLNTIR_AWS_REGION}" \
    --target "${PLNTIR_RELAY_INSTANCE_ID}" \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters "${parameters}"
