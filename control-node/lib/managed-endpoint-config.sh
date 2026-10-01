#!/usr/bin/env bash

# shared, non-executable configuration loader for the plntir control node-to-mac hop.
# the defaults preserve the currently deployed legacy transport. a root-owned
# configuration file switches all three jobs to the forced-command mac agent.

load_managed_mac_config() {
    local config=/etc/plntir/managed-endpoint.conf
    local line name value owner mode
    local -A seen=()

    MAC_TRANSPORT=legacy
    MAC_TARGET=bootstrapadmin@100.101.0.2
    MAC_MONITOR_KEY=/home/admin/.ssh/plntir_control_to_endpoint_ed25519
    MAC_RESPONSE_KEY=/home/admin/.ssh/plntir_control_to_endpoint_ed25519
    MAC_ARCHIVE_KEY=
    MAC_ARCHIVE_RECIPIENT=
    MAC_HOST_KEYS=/home/admin/.ssh/managed_plntir_endpoint_known_hosts
    MAC_MANAGED_HOME=/Users/plntir-operator

    if [[ -e ${config} ]]; then
        if [[ -L ${config} || ! -f ${config} ]]; then
            printf 'Unsafe managed Mac configuration type: %s\n' "${config}" >&2
            return 78
        fi
        read -r owner mode < <(/usr/bin/stat -Lc '%u %a' "${config}")
        if [[ ${owner} != 0 || ! ${mode} =~ ^[0-7]{3,4}$ || $((8#${mode} & 0022)) -ne 0 ]]; then
            printf 'Managed Mac configuration must be root-owned and not group/world writable.\n' >&2
            return 78
        fi

        while IFS= read -r line || [[ -n ${line} ]]; do
            [[ ${line} =~ ^[[:space:]]*$ || ${line} =~ ^[[:space:]]*# ]] && continue
            if [[ ! ${line} =~ ^(MAC_TRANSPORT|MAC_TARGET|MAC_MONITOR_KEY|MAC_RESPONSE_KEY|MAC_ARCHIVE_KEY|MAC_ARCHIVE_RECIPIENT|MAC_HOST_KEYS|MAC_MANAGED_HOME)=([^[:space:]]+)$ ]]; then
                printf 'Invalid managed Mac configuration line.\n' >&2
                return 78
            fi
            name=${BASH_REMATCH[1]}
            value=${BASH_REMATCH[2]}
            if [[ -n ${seen[${name}]+x} ]]; then
                printf 'Duplicate managed Mac configuration key: %s\n' "${name}" >&2
                return 78
            fi
            seen[${name}]=1
            case ${name} in
            MAC_TRANSPORT) MAC_TRANSPORT=${value} ;;
            MAC_TARGET) MAC_TARGET=${value} ;;
            MAC_MONITOR_KEY) MAC_MONITOR_KEY=${value} ;;
            MAC_RESPONSE_KEY) MAC_RESPONSE_KEY=${value} ;;
            MAC_ARCHIVE_KEY) MAC_ARCHIVE_KEY=${value} ;;
            MAC_ARCHIVE_RECIPIENT) MAC_ARCHIVE_RECIPIENT=${value} ;;
            MAC_HOST_KEYS) MAC_HOST_KEYS=${value} ;;
            MAC_MANAGED_HOME) MAC_MANAGED_HOME=${value} ;;
            esac
        done <"${config}"
    fi

    [[ ${MAC_TRANSPORT} == legacy || ${MAC_TRANSPORT} == dispatch ]] || {
        printf 'Invalid MAC_TRANSPORT: %s\n' "${MAC_TRANSPORT}" >&2
        return 78
    }
    [[ ${MAC_TARGET} =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$ ]] || {
        printf 'Invalid MAC_TARGET.\n' >&2
        return 78
    }
    [[ ${MAC_MONITOR_KEY} =~ ^/home/admin/[.]ssh/[A-Za-z0-9._-]+$ ]] || {
        printf 'Invalid MAC_MONITOR_KEY.\n' >&2
        return 78
    }
    [[ ${MAC_RESPONSE_KEY} =~ ^/home/admin/[.]ssh/[A-Za-z0-9._-]+$ ]] || {
        printf 'Invalid MAC_RESPONSE_KEY.\n' >&2
        return 78
    }
    if [[ -n ${MAC_ARCHIVE_KEY} || -n ${MAC_ARCHIVE_RECIPIENT} ]]; then
        [[ ${MAC_ARCHIVE_KEY} =~ ^/home/admin/[.]ssh/[A-Za-z0-9._-]+$ ]] || {
            printf 'Invalid MAC_ARCHIVE_KEY.\n' >&2
            return 78
        }
        [[ ${MAC_ARCHIVE_RECIPIENT} =~ ^[A-Fa-f0-9]{40,64}$ ]] || {
            printf 'Invalid MAC_ARCHIVE_RECIPIENT.\n' >&2
            return 78
        }
        [[ -r ${MAC_ARCHIVE_KEY} ]] || {
            printf 'The configured archive SSH key is unreadable.\n' >&2
            return 78
        }
    fi
    [[ ${MAC_HOST_KEYS} =~ ^/home/admin/[.]ssh/[A-Za-z0-9._-]+$ ]] || {
        printf 'Invalid MAC_HOST_KEYS.\n' >&2
        return 78
    }
    [[ ${MAC_MANAGED_HOME} =~ ^/Users/[A-Za-z0-9._-]+$ ]] || {
        printf 'Invalid MAC_MANAGED_HOME.\n' >&2
        return 78
    }
    [[ -r ${MAC_MONITOR_KEY} && -r ${MAC_RESPONSE_KEY} && -r ${MAC_HOST_KEYS} ]] || {
        printf 'A configured managed Mac SSH file is unreadable.\n' >&2
        return 78
    }

    readonly MAC_TRANSPORT MAC_TARGET MAC_MONITOR_KEY MAC_RESPONSE_KEY
    readonly MAC_ARCHIVE_KEY MAC_ARCHIVE_RECIPIENT
    readonly MAC_HOST_KEYS MAC_MANAGED_HOME
}
