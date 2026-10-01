#!/usr/bin/env bash
set -u
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C

health_path=/var/lib/plntir/monitor/mac-latest.json
history_path=/var/lib/plntir/monitor/mac-health.jsonl
security_path=/var/lib/plntir/monitor/security-latest.json
all_users_export_path=/var/lib/plntir/monitor/all-users-export.json
monitor_root=/var/lib/plntir/monitor
retrieved_root=/var/lib/plntir/retrieved

json_file_or_null() {
    if [[ -r $1 ]]; then
        /usr/bin/jq -c . "$1" 2>/dev/null || printf 'null'
    else
        printf 'null'
    fi
}

unit_active() {
    if /usr/bin/systemctl is-active --quiet "$1" 2>/dev/null; then
        printf 'true'
    else
        printf 'false'
    fi
}

unit_enabled() {
    local state
    state=$(/usr/bin/systemctl is-enabled "$1" 2>/dev/null || true)
    case ${state} in
    enabled|enabled-runtime) printf 'true' ;;
    *) printf 'false' ;;
    esac
}

timer_json() {
    local timer="$1"
    local service="$2"
    local active enabled last_trigger next_trigger service_result exec_status
    active=$(unit_active "$timer")
    enabled=$(unit_enabled "$timer")
    last_trigger=$(/usr/bin/systemctl show "$timer" --property=LastTriggerUSec --value 2>/dev/null || true)
    next_trigger=$(/usr/bin/systemctl show "$timer" --property=NextElapseUSecRealtime --value 2>/dev/null || true)
    service_result=$(/usr/bin/systemctl show "$service" --property=Result --value 2>/dev/null || true)
    exec_status=$(/usr/bin/systemctl show "$service" --property=ExecMainStatus --value 2>/dev/null || true)
    [[ $exec_status =~ ^[0-9]+$ ]] || exec_status=255
    /usr/bin/jq -cn \
        --argjson active "$active" \
        --argjson enabled "$enabled" \
        --arg last_trigger "$last_trigger" \
        --arg next_trigger "$next_trigger" \
        --arg service_result "$service_result" \
        --argjson exec_status "$exec_status" \
        '{active:$active,enabled:$enabled,last_trigger:$last_trigger,next_trigger:$next_trigger,service_result:$service_result,exec_main_status:$exec_status}'
}

health_json=$(json_file_or_null "$health_path")
security_json=$(json_file_or_null "$security_path")
all_users_export_json=$(json_file_or_null "$all_users_export_path")

online_line=''
offline_line=''
if [[ -r $history_path ]]; then
    online_line=$(/usr/bin/tac "$history_path" 2>/dev/null | /usr/bin/grep -m1 '"state":"online"' || true)
    offline_line=$(/usr/bin/tac "$history_path" 2>/dev/null | /usr/bin/grep -m1 '"state":"offline"' || true)
fi
last_online=''
last_offline=''
last_online_health='null'
if [[ -n $online_line ]]; then
    last_online=$(printf '%s\n' "$online_line" | /usr/bin/jq -r '.timestamp // empty' 2>/dev/null || true)
    last_online_health=$(printf '%s\n' "$online_line" | /usr/bin/jq -c . 2>/dev/null || printf 'null')
fi
if [[ -n $offline_line ]]; then
    last_offline=$(printf '%s\n' "$offline_line" | /usr/bin/jq -r '.timestamp // empty' 2>/dev/null || true)
fi

collected_at=$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
node_hostname=$(/bin/hostname 2>/dev/null || printf unknown)
uptime_seconds=$(/usr/bin/awk -F. '{print $1}' /proc/uptime 2>/dev/null || printf 0)
read -r load_1 load_5 load_15 _ </proc/loadavg
memory_total_kb=$(/usr/bin/awk '/^MemTotal:/ {print $2}' /proc/meminfo)
memory_available_kb=$(/usr/bin/awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
read -r root_total_kb root_used_kb _ root_used_percent < <(/bin/df -Pk / | /usr/bin/awk 'NR==2 {gsub(/%/, "", $5); print $2, $3, $4, $5}')

warp_service_active=$(unit_active warp-svc.service)
warp_output=$(/usr/bin/warp-cli status 2>/dev/null || true)
mesh_ip=$(/usr/sbin/ip -4 -o address show dev CloudflareWARP 2>/dev/null | /usr/bin/awk 'NR==1 {sub(/\/.*/, "", $4); print $4}')
warp_connected=false
warp_network=$(printf '%s\n' "$warp_output" | /bin/sed -n 's/^Network: //p' | /usr/bin/head -n 1)
if printf '%s\n' "$warp_output" | /usr/bin/grep -Fqx 'Status update: Connected'; then
    warp_connected=true
elif [[ ${warp_service_active} == true && -n ${mesh_ip} ]]; then
    # some service accounts cannot query warp-cli without accepting terms.
    # service state plus the assigned mesh address is a read-only fallback.
    warp_connected=true
    warp_network=mesh-interface
fi

fail2ban_active=$(unit_active fail2ban.service)
ntp_synchronized=false
if [[ $(/usr/bin/timedatectl show --property=NTPSynchronized --value 2>/dev/null || true) == yes ]]; then
    ntp_synchronized=true
fi
auto_updates_enabled=$(unit_enabled apt-daily-upgrade.timer)
reboot_required=false
[[ -e /var/run/reboot-required ]] && reboot_required=true

public_ssh=unknown
if sudo -n /usr/sbin/nft list chain inet host_filter input 2>/dev/null | /usr/bin/grep -Eq '^[[:space:]]*tcp dport 22 accept$'; then
    public_ssh=open_bootstrap
elif sudo -n /usr/sbin/nft list chain inet host_filter input >/dev/null 2>&1; then
    public_ssh=restricted
fi

control_node_timer=$(timer_json plntir-endpoint-health.timer plntir-endpoint-health.service)
security_timer=$(timer_json plntir-endpoint-security.timer plntir-endpoint-security.service)
export_readiness_timer=$(timer_json plntir-secure-archive-readiness.timer plntir-secure-archive-readiness.service)

monitor_bytes=$(/usr/bin/du -sb "$monitor_root" 2>/dev/null | /usr/bin/awk '{print $1}')
retrieved_bytes=$(/usr/bin/du -sb "$retrieved_root" 2>/dev/null | /usr/bin/awk '{print $1}')
[[ $monitor_bytes =~ ^[0-9]+$ ]] || monitor_bytes=0
[[ $retrieved_bytes =~ ^[0-9]+$ ]] || retrieved_bytes=0

archive_count=$(/usr/bin/find "$retrieved_root" -type f \( -name '*.tar.gz' -o -name '*.tar.zst.gpg' \) 2>/dev/null | /usr/bin/wc -l)
archive_count=${archive_count//[[:space:]]/}
archive_bytes=$(/usr/bin/find "$retrieved_root" -type f \( -name '*.tar.gz' -o -name '*.tar.zst.gpg' \) -printf '%s\n' 2>/dev/null | /usr/bin/awk '{sum += $1} END {printf "%.0f", sum}')
[[ $archive_count =~ ^[0-9]+$ ]] || archive_count=0
[[ $archive_bytes =~ ^[0-9]+$ ]] || archive_bytes=0
latest_epoch=0
latest_archive_bytes=0
latest_record=$(/usr/bin/find "$retrieved_root" -type f \( -name '*.tar.gz' -o -name '*.tar.zst.gpg' \) -printf '%T@ %s\n' 2>/dev/null | /usr/bin/sort -nr | /usr/bin/head -n 1)
if [[ -n $latest_record ]]; then
    read -r latest_epoch latest_archive_bytes < <(printf '%s\n' "$latest_record")
fi
[[ $latest_epoch =~ ^[0-9]+([.][0-9]+)?$ ]] || latest_epoch=0
[[ $latest_archive_bytes =~ ^[0-9]+$ ]] || latest_archive_bytes=0

events_json=$(sudo -n /usr/bin/journalctl -t plntir-endpoint-health -n 12 --no-pager -o json 2>/dev/null | /usr/bin/jq -sc '[.[] | {timestamp: (((.__REALTIME_TIMESTAMP | tonumber) / 1000000) | strftime("%Y-%m-%dT%H:%M:%SZ")), message: (.MESSAGE // "")} ]' 2>/dev/null || true)
[[ -n $events_json ]] || events_json='[]'

/usr/bin/jq -cn \
    --arg collected_at "$collected_at" \
    --arg node_hostname "$node_hostname" \
    --argjson uptime_seconds "$uptime_seconds" \
    --argjson load_1 "$load_1" \
    --argjson load_5 "$load_5" \
    --argjson load_15 "$load_15" \
    --argjson memory_total_bytes "$((memory_total_kb * 1024))" \
    --argjson memory_available_bytes "$((memory_available_kb * 1024))" \
    --argjson root_total_bytes "$((root_total_kb * 1024))" \
    --argjson root_used_bytes "$((root_used_kb * 1024))" \
    --argjson root_used_percent "$root_used_percent" \
    --argjson warp_service_active "$warp_service_active" \
    --argjson warp_connected "$warp_connected" \
    --arg warp_network "$warp_network" \
    --arg mesh_ip "$mesh_ip" \
    --argjson fail2ban_active "$fail2ban_active" \
    --argjson ntp_synchronized "$ntp_synchronized" \
    --argjson auto_updates_enabled "$auto_updates_enabled" \
    --argjson reboot_required "$reboot_required" \
    --arg public_ssh "$public_ssh" \
    --argjson health "$health_json" \
    --arg last_online "$last_online" \
    --arg last_offline "$last_offline" \
    --argjson last_online_health "$last_online_health" \
    --argjson security "$security_json" \
    --argjson all_users_export "$all_users_export_json" \
    --argjson control_node_timer "$control_node_timer" \
    --argjson security_timer "$security_timer" \
    --argjson export_readiness_timer "$export_readiness_timer" \
    --argjson monitor_bytes "$monitor_bytes" \
    --argjson retrieved_bytes "$retrieved_bytes" \
    --argjson archive_count "$archive_count" \
    --argjson archive_bytes "$archive_bytes" \
    --argjson latest_epoch "$latest_epoch" \
    --argjson latest_archive_bytes "$latest_archive_bytes" \
    --argjson events "$events_json" \
    '{
        schema_version: 2,
        collected_at: $collected_at,
        connection: {target: "", round_trip_ms: 0},
        node: {
            hostname: $node_hostname,
            uptime_seconds: $uptime_seconds,
            load_1: $load_1,
            load_5: $load_5,
            load_15: $load_15,
            memory_total_bytes: $memory_total_bytes,
            memory_available_bytes: $memory_available_bytes,
            root_total_bytes: $root_total_bytes,
            root_used_bytes: $root_used_bytes,
            root_used_percent: $root_used_percent,
            warp_service_active: $warp_service_active,
            warp_connected: $warp_connected,
            warp_network: $warp_network,
            mesh_ip: $mesh_ip,
            fail2ban_active: $fail2ban_active,
            ntp_synchronized: $ntp_synchronized,
            auto_updates_enabled: $auto_updates_enabled,
            reboot_required: $reboot_required,
            public_ssh: $public_ssh
        },
        mac: {
            health: $health,
            last_online: $last_online,
            last_offline: $last_offline,
            last_online_health: $last_online_health,
            security: $security
        },
        timers: {control_node: $control_node_timer, security: $security_timer, export_readiness: $export_readiness_timer},
        all_users_export: $all_users_export,
        storage: {monitor_bytes: $monitor_bytes, retrieved_bytes: $retrieved_bytes},
        retrieval: {
            archive_count: $archive_count,
            archive_bytes: $archive_bytes,
            latest_epoch: $latest_epoch,
            latest_archive_bytes: $latest_archive_bytes
        },
        events: $events
    }'
