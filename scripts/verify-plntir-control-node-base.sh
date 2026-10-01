#!/usr/bin/env bash
set -Eeuo pipefail

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

check 'sshd configuration syntax' sudo sshd -t
check 'root SSH disabled' sh -c "sudo sshd -T | grep -Fxq 'permitrootlogin no'"
check 'password SSH disabled' sh -c "sudo sshd -T | grep -Fxq 'passwordauthentication no'"
check 'X11 forwarding disabled' sh -c "sudo sshd -T | grep -Fxq 'x11forwarding no'"
check 'TCP forwarding disabled' sh -c "sudo sshd -T | grep -Fxq 'allowtcpforwarding no'"
check 'nftables active' systemctl is-active --quiet nftables
check 'host firewall table loaded' sh -c 'sudo nft list table inet host_filter'
check 'WARP nftables table preserved' sh -c 'sudo nft list table inet cloudflare-warp'
check 'mesh SSH explicitly allowed' sh -c "sudo nft list chain inet host_filter input | grep -Fq 'iifname \"CloudflareWARP\" tcp dport 22 accept'"
check 'fail2ban active' systemctl is-active --quiet fail2ban
check 'sshd jail active' sh -c 'sudo fail2ban-client status sshd'
check 'mesh excluded from SSH bans' sh -c "sudo fail2ban-client get sshd ignoreip | grep -Fq '100.96.0.0/12'"
check 'auditd active' systemctl is-active --quiet auditd
check 'audit rules loaded' sh -c "sudo auditctl -l | grep -Fq '/opt/plntir'"
check 'AppArmor active' systemctl is-active --quiet apparmor
check 'Docker active' systemctl is-active --quiet docker
check 'Docker bound to no TCP socket' sh -c "! sudo ss -lntp | grep -Eq 'docker.*:(2375|2376)'"
check 'LLMNR listener absent' sh -c "! sudo ss -lntup | grep -q ':5355'"
check 'swap enabled' sh -c 'sudo swapon --show=NAME --noheadings --raw | grep -Fxq /swapfile'
check 'automatic upgrades enabled' systemctl is-enabled --quiet apt-daily-upgrade.timer
check 'security updates current' sh -c "sudo apt-get -s upgrade | grep -Fq '0 upgraded'"

exit "${failed}"
