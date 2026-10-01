#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root.\n' >&2
    exit 1
fi

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

check 'observer account exists' id macobserver
check 'observer display name is branded' sh -c \
    "getent passwd macobserver | awk -F: '{exit !(\$5 == \"Plntir Observer Service\")}'"
check 'observer home is branded' sh -c \
    "getent passwd macobserver | awk -F: '{exit !(\$6 == \"/var/lib/plntir-observer\")}'"
check 'observer password is locked' sh -c \
    "passwd -S macobserver | awk '{exit !(\$2 == \"L\")}'"
check 'control-plane group exists' getent group plntircontrol
check 'operator belongs to control-plane group' sh -c \
    "id -nG admin | tr ' ' '\\n' | grep -Fxq plntircontrol"
check 'observer belongs to control-plane group' sh -c \
    "id -nG macobserver | tr ' ' '\\n' | grep -Fxq plntircontrol"
check 'managed Mac config loader is installed' test -r \
    /opt/plntir/lib/managed-endpoint-config.sh
check 'observer key is restricted' sh -c \
    "grep -Eq '^(from=\"[^\"]+\",)?restrict[[:space:]]+(ssh-|ecdsa-)' /var/lib/plntir-observer/.ssh/authorized_keys"
check 'sudoers syntax' visudo -cf /etc/sudoers
check 'observer sudo is limited to nft' sh -c \
    "sudo -l -U macobserver | grep -Fq '/usr/sbin/nft list chain inet host_filter input'"
check 'observer sudo is limited to state events' sh -c \
    "sudo -l -U macobserver | grep -Fq '/usr/bin/journalctl -t plntir-endpoint-health -n 12 --no-pager -o json'"
check 'observer has no blanket NOPASSWD' sh -c \
    "! sudo -l -U macobserver | grep -Eq 'NOPASSWD:[[:space:]]*(ALL|/bin/(ba)?sh)'"
check 'sshd syntax' sshd -t
check 'observer forced command active' sh -c \
    "sshd -T -C user=macobserver,host=localhost,addr=127.0.0.1 | grep -Fxq 'forcecommand /opt/plntir/bin/plntir-observer-dispatch'"
check 'observer forwarding disabled' sh -c \
    "sshd -T -C user=macobserver,host=localhost,addr=127.0.0.1 | grep -Fxq 'disableforwarding yes'"
check 'Plntir health timer enabled' systemctl is-enabled --quiet plntir-endpoint-health.timer
check 'Plntir health timer active' systemctl is-active --quiet plntir-endpoint-health.timer
check 'security timer enabled' systemctl is-enabled --quiet plntir-endpoint-security.timer
check 'security timer active' systemctl is-active --quiet plntir-endpoint-security.timer
check 'export readiness timer is not enabled' sh -c \
    "! systemctl is-enabled --quiet plntir-secure-archive-readiness.timer"
check 'export readiness timer is inactive' sh -c \
    "! systemctl is-active --quiet plntir-secure-archive-readiness.timer"
check 'on-demand all-user export service is installed' systemctl cat plntir-secure-archive.service
check 'admin forwarding is scoped to the Mac SSH port' sh -c \
    "sshd -T -C user=admin,host=localhost,addr=127.0.0.1 | grep -Fxq 'allowtcpforwarding local' && sshd -T -C user=admin,host=localhost,addr=127.0.0.1 | grep -Fxq 'permitopen 100.101.0.2:22 127.0.0.1:1337'"
check 'observer forwarding remains disabled' sh -c \
    "sshd -T -C user=macobserver,host=localhost,addr=127.0.0.1 | grep -Fxq 'disableforwarding yes'"
check 'observer collector emits schema v2' sh -c \
    "runuser -u macobserver -- env SSH_ORIGINAL_COMMAND=status-v2 /opt/plntir/bin/plntir-observer-dispatch | jq -e '.schema_version == 2 and (.node.hostname | length > 0)'"
check 'observer rejects arbitrary commands' sh -c \
    "! runuser -u macobserver -- env SSH_ORIGINAL_COMMAND='bash -s --' /opt/plntir/bin/plntir-observer-dispatch"

if [[ -e /etc/plntir/managed-endpoint.conf ]]; then
    check 'managed Mac config is a regular file' test ! -L \
        /etc/plntir/managed-endpoint.conf
    check 'managed Mac config ownership and mode are safe' sh -c \
        "test \"\$(stat -Lc '%u %a' /etc/plntir/managed-endpoint.conf)\" = '0 640'"
    check 'managed Mac config parses as operator' runuser -u admin -- /bin/bash -c \
        "source /opt/plntir/lib/managed-endpoint-config.sh; load_managed_mac_config; [[ \${MAC_TRANSPORT} == dispatch ]]"
    check 'monitor and response keys are distinct' sh -c \
        "monitor=\$(ssh-keygen -y -P '' -f /home/admin/.ssh/plntir_endpoint_monitor_ed25519) && response=\$(ssh-keygen -y -P '' -f /home/admin/.ssh/plntir_endpoint_response_ed25519) && test \"\$monitor\" != \"\$response\""
    # shellcheck disable=SC2016
    if runuser -u admin -- /bin/bash -c \
        'source /opt/plntir/lib/managed-endpoint-config.sh; load_managed_mac_config; [[ -n ${MAC_ARCHIVE_KEY} ]]' >/dev/null 2>&1; then
        check 'monitor, response, and archive keys are distinct' sh -c \
            "monitor=\$(ssh-keygen -y -P '' -f /home/admin/.ssh/plntir_endpoint_monitor_ed25519) && response=\$(ssh-keygen -y -P '' -f /home/admin/.ssh/plntir_endpoint_response_ed25519) && archive=\$(ssh-keygen -y -P '' -f /home/admin/.ssh/plntir_endpoint_archive_ed25519) && test \"\$monitor\" != \"\$archive\" && test \"\$response\" != \"\$archive\""
        check 'archive GPG keyring contains no private key' sh -c \
            "test -z \"\$(runuser -u admin -- gpg --homedir /var/lib/plntir/archive-gnupg --batch --with-colons --list-secret-keys 2>/dev/null | grep '^sec:')\""
        check 'all-user export status is valid' sh -c \
            "jq -e '.schema_version == 1 and (.state == \"ready\" or .state == \"blocked\" or .state == \"unreachable\" or .state == \"complete\" or .state == \"failed\")' /var/lib/plntir/monitor/all-users-export.json"
    fi
else
    printf 'INFO managed Mac transport remains on legacy defaults\n'
fi

exit "${failed}"
