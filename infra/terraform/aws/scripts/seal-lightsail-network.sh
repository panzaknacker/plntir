#!/bin/sh
set -eu

export AWS_PAGER=
umask 077

: "${PLNTIR_AWS_ACCOUNT_ID:?}"
: "${PLNTIR_EXPECTED_DEFAULT_VPC_ID:?}"
: "${PLNTIR_EXPECTED_RELAY_SUBNET_ID:?}"
: "${PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON:?}"
: "${PLNTIR_PROTECTED_WATCH_ARN:?}"
: "${PLNTIR_REGION:?}"
: "${PLNTIR_SEAL_MODE:?}"

[ "${PLNTIR_REGION}" = "eu-central-1" ] || {
    printf '%s\n' 'Refusing a Lightsail network seal outside eu-central-1.' >&2
    exit 77
}
case ${PLNTIR_SEAL_MODE} in
ports | peer | both) ;;
*)
    printf '%s\n' 'PLNTIR_SEAL_MODE must be ports, peer, or both.' >&2
    exit 64
    ;;
esac

workdir=$(mktemp -d /tmp/plntir-lightsail-seal.XXXXXX)
cleanup() {
    case ${workdir} in
    /tmp/plntir-lightsail-seal.*) rm -rf "${workdir}" ;;
    *) printf '%s\n' 'Refusing unsafe temporary cleanup path.' >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "${PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON}" >"${workdir}/names.json"
jq -e '
    type == "array" and
    sort == ["plntir-core-01", "plntir-edge-01", "plntir-mdm-01", "plntir-siem-01"] and
    (all(.[]; test("^plntir-(core|edge|mdm|siem)-01$")))
' "${workdir}/names.json" >/dev/null

caller_account=$(aws sts get-caller-identity --query Account --output text)
[ "${caller_account}" = "${PLNTIR_AWS_ACCOUNT_ID}" ] || {
    printf '%s\n' 'AWS caller account does not match the approved Plntir account.' >&2
    exit 77
}

if [ "${PLNTIR_SEAL_MODE}" = ports ] || [ "${PLNTIR_SEAL_MODE}" = both ]; then
    jq -r '.[]' "${workdir}/names.json" | while IFS= read -r instance_name; do
        aws lightsail get-instance \
            --region "${PLNTIR_REGION}" \
            --instance-name "${instance_name}" \
            --output json >"${workdir}/${instance_name}.json"
        instance_arn=$(jq -r '.instance.arn' "${workdir}/${instance_name}.json")
        [ "${instance_arn}" != "${PLNTIR_PROTECTED_WATCH_ARN}" ] || {
            printf '%s\n' 'Refusing to inspect or seal the protected Watch as a new node.' >&2
            exit 77
        }
    done

    jq -r '.[]' "${workdir}/names.json" | while IFS= read -r instance_name; do
        aws lightsail get-instance-port-states \
            --region "${PLNTIR_REGION}" \
            --instance-name "${instance_name}" \
            --output json >"${workdir}/${instance_name}-ports.json"
        jq -c '.portStates[] | select(.state == "open") | {fromPort, toPort, protocol}' \
            "${workdir}/${instance_name}-ports.json" >"${workdir}/${instance_name}-open.jsonl"
        while IFS= read -r port_info; do
            [ -n "${port_info}" ] || continue
            aws lightsail close-instance-public-ports \
                --region "${PLNTIR_REGION}" \
                --instance-name "${instance_name}" \
                --port-info "${port_info}" >/dev/null
        done <"${workdir}/${instance_name}-open.jsonl"

        aws lightsail get-instance-port-states \
            --region "${PLNTIR_REGION}" \
            --instance-name "${instance_name}" \
            --output json >"${workdir}/${instance_name}-ports-after.json"
        jq -e 'all(.portStates[]; .state != "open")' \
            "${workdir}/${instance_name}-ports-after.json" >/dev/null
    done
fi

if [ "${PLNTIR_SEAL_MODE}" = peer ] || [ "${PLNTIR_SEAL_MODE}" = both ]; then
    aws ec2 describe-vpcs \
        --region "${PLNTIR_REGION}" \
        --vpc-ids "${PLNTIR_EXPECTED_DEFAULT_VPC_ID}" \
        --output json >"${workdir}/vpc.json"
    jq -e '.Vpcs | length == 1 and .[0].IsDefault == true' "${workdir}/vpc.json" >/dev/null

    aws ec2 describe-subnets \
        --region "${PLNTIR_REGION}" \
        --subnet-ids "${PLNTIR_EXPECTED_RELAY_SUBNET_ID}" \
        --output json >"${workdir}/subnet.json"
    jq -e --arg vpc "${PLNTIR_EXPECTED_DEFAULT_VPC_ID}" \
        '.Subnets | length == 1 and .[0].VpcId == $vpc' \
        "${workdir}/subnet.json" >/dev/null

    peer_ready=false
    if aws lightsail get-peer-vpc --region "${PLNTIR_REGION}" --output json >"${workdir}/peer.json" 2>/dev/null; then
        if jq -e '.peering.state == "succeeded"' "${workdir}/peer.json" >/dev/null; then
            peer_ready=true
        fi
    fi
    if [ "${peer_ready}" != true ]; then
        aws lightsail peer-vpc --region "${PLNTIR_REGION}" --output json >"${workdir}/peer-start.json"
        attempt=0
        while [ "${attempt}" -lt 60 ]; do
            if aws lightsail get-peer-vpc --region "${PLNTIR_REGION}" --output json >"${workdir}/peer.json" 2>/dev/null &&
                jq -e '.peering.state == "succeeded"' "${workdir}/peer.json" >/dev/null; then
                peer_ready=true
                break
            fi
            if jq -e '.peering.state == "failed"' "${workdir}/peer.json" >/dev/null 2>&1; then
                printf '%s\n' 'Lightsail VPC peering entered failed state.' >&2
                exit 75
            fi
            sleep 2
            attempt=$((attempt + 1))
        done
    fi
    [ "${peer_ready}" = true ] || {
        printf '%s\n' 'Lightsail VPC peering did not become ready within 120 seconds.' >&2
        exit 75
    }
fi

printf 'PASS Lightsail network seal mode=%s.\n' "${PLNTIR_SEAL_MODE}"
