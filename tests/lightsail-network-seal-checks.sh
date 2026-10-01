#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
workdir=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "${workdir}"' EXIT

mock_bin=${workdir}/bin
mock_state=${workdir}/state
/usr/bin/install -d -m 0700 "${mock_bin}" "${mock_state}"

/usr/bin/tee "${mock_bin}/aws" >/dev/null <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
: "${MOCK_AWS_STATE:?}"
printf '%q ' "$@" >>"${MOCK_AWS_STATE}/calls"
printf '\n' >>"${MOCK_AWS_STATE}/calls"

service=${1-}
action=${2-}
shift 2 || true

argument() {
    local wanted=$1
    shift
    while (($#)); do
        if [[ $1 == "${wanted}" && $# -ge 2 ]]; then
            printf '%s\n' "$2"
            return 0
        fi
        shift
    done
    return 1
}

case "${service}:${action}" in
sts:get-caller-identity)
    printf '%s\n' "${MOCK_CALLER_ACCOUNT:-444455556666}"
    ;;
ec2:describe-vpcs)
    vpc=$(argument --vpc-ids "$@")
    printf '{"Vpcs":[{"VpcId":"%s","IsDefault":true}]}\n' "${vpc}"
    ;;
ec2:describe-subnets)
    subnet=$(argument --subnet-ids "$@")
    printf '{"Subnets":[{"SubnetId":"%s","VpcId":"%s"}]}\n' \
        "${subnet}" "${MOCK_EXPECTED_VPC:-vpc-0123456789abcdef0}"
    ;;
lightsail:get-instance)
    name=$(argument --instance-name "$@")
    if [[ ${name} == "${MOCK_PROTECT_NAME:-never}" ]]; then
        arn=${MOCK_PROTECTED_ARN:?}
    else
        arn="arn:aws:lightsail:eu-central-1:444455556666:Instance/mock-${name}"
    fi
    printf '{"instance":{"name":"%s","arn":"%s"}}\n' "${name}" "${arn}"
    ;;
lightsail:get-instance-port-states)
    name=$(argument --instance-name "$@")
    ssh_state=open
    web_state=open
    [[ ! -e ${MOCK_AWS_STATE}/closed-${name}-22 ]] || ssh_state=closed
    [[ ! -e ${MOCK_AWS_STATE}/closed-${name}-80 ]] || web_state=closed
    printf '{"portStates":[{"fromPort":22,"toPort":22,"protocol":"tcp","state":"%s"},{"fromPort":80,"toPort":80,"protocol":"tcp","state":"%s"}]}\n' \
        "${ssh_state}" "${web_state}"
    ;;
lightsail:close-instance-public-ports)
    name=$(argument --instance-name "$@")
    port_info=$(argument --port-info "$@")
    port=$(printf '%s\n' "${port_info}" | jq -r '.fromPort')
    : >"${MOCK_AWS_STATE}/closed-${name}-${port}"
    printf '{}\n'
    ;;
lightsail:get-peer-vpc)
    if [[ -e ${MOCK_AWS_STATE}/peer-started ]]; then
        printf '{"peering":{"state":"succeeded"}}\n'
    else
        printf '{"peering":{"state":"pending"}}\n'
    fi
    ;;
lightsail:peer-vpc)
    : >"${MOCK_AWS_STATE}/peer-started"
    printf '{"operation":{"status":"Succeeded"}}\n'
    ;;
*)
    printf 'Unexpected mock AWS call: %s %s\n' "${service}" "${action}" >&2
    exit 64
    ;;
esac
MOCK
/bin/chmod 0755 "${mock_bin}/aws"

readonly protected_watch_arn=arn:aws:lightsail:eu-central-1:444455556666:Instance/e40d6806-5f0b-4cfd-8ee9-36ac8f5af13d
readonly expected_names='["plntir-core-01","plntir-edge-01","plntir-mdm-01","plntir-siem-01"]'

run_seal() {
    local seal_mode=${1:-both}
    PATH="${mock_bin}:${PATH}" \
        MOCK_AWS_STATE="${mock_state}" \
        MOCK_EXPECTED_VPC=vpc-0123456789abcdef0 \
        MOCK_PROTECTED_ARN="${protected_watch_arn}" \
        PLNTIR_AWS_ACCOUNT_ID=444455556666 \
        PLNTIR_EXPECTED_DEFAULT_VPC_ID=vpc-0123456789abcdef0 \
        PLNTIR_EXPECTED_RELAY_SUBNET_ID=subnet-0123456789abcdef0 \
        PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON="${expected_names}" \
        PLNTIR_PROTECTED_WATCH_ARN="${protected_watch_arn}" \
        PLNTIR_REGION=eu-central-1 \
        PLNTIR_SEAL_MODE="${seal_mode}" \
        "${ROOT}/infra/terraform/aws/scripts/seal-lightsail-network.sh"
}

run_seal >/dev/null
[[ $(/usr/bin/find "${mock_state}" -maxdepth 1 -type f -name 'closed-*' | /usr/bin/wc -l) -eq 8 ]]
[[ -e ${mock_state}/peer-started ]]
if /usr/bin/grep -Eq 'open-instance-public-ports|put-instance-public-ports' "${mock_state}/calls"; then
    printf 'The network seal attempted to open or replace public ports.\n' >&2
    exit 1
fi

/bin/rm -f "${mock_state}"/closed-* "${mock_state}/peer-started" "${mock_state}/calls"
run_seal ports >/dev/null
[[ ! -e ${mock_state}/peer-started ]]
if /usr/bin/grep -Eq 'describe-vpcs|describe-subnets|peer-vpc' "${mock_state}/calls"; then
    printf 'Port-only seal attempted a peering operation.\n' >&2
    exit 1
fi

/bin/rm -f "${mock_state}"/closed-* "${mock_state}/calls"
run_seal peer >/dev/null
[[ -e ${mock_state}/peer-started ]]
if /usr/bin/grep -Eq 'get-instance |get-instance-port-states|close-instance-public-ports' "${mock_state}/calls"; then
    printf 'Peer-only seal attempted a Lightsail instance-port operation.\n' >&2
    exit 1
fi

/bin/rm -f "${mock_state}"/closed-* "${mock_state}/peer-started" "${mock_state}/calls"
if MOCK_PROTECT_NAME=plntir-siem-01 run_seal ports >/dev/null 2>&1; then
    printf 'The network seal accepted the protected Watch ARN.\n' >&2
    exit 1
fi
[[ ! -e ${mock_state}/peer-started ]]
if /usr/bin/find "${mock_state}" -maxdepth 1 -type f -name 'closed-*' | /usr/bin/grep -q .; then
    printf 'The protected-ARN failure closed ports before refusing.\n' >&2
    exit 1
fi

if PATH="${mock_bin}:${PATH}" \
    MOCK_AWS_STATE="${mock_state}" \
    PLNTIR_AWS_ACCOUNT_ID=444455556666 \
    PLNTIR_EXPECTED_DEFAULT_VPC_ID=vpc-0123456789abcdef0 \
    PLNTIR_EXPECTED_RELAY_SUBNET_ID=subnet-0123456789abcdef0 \
    PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON='["plntir-core-01"]' \
    PLNTIR_PROTECTED_WATCH_ARN="${protected_watch_arn}" \
    PLNTIR_REGION=eu-central-1 \
    PLNTIR_SEAL_MODE=both \
    "${ROOT}/infra/terraform/aws/scripts/seal-lightsail-network.sh" >/dev/null 2>&1; then
    printf 'The network seal accepted an incomplete instance set.\n' >&2
    exit 1
fi

printf 'Lightsail network-seal checks passed.\n'
