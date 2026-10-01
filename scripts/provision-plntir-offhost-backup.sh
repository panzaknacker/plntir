#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run as root on the Plntir Control Node.\n' >&2
    exit 1
fi
if [[ $# -ne 3 ]]; then
    printf 'usage: %s BUNDLE_DIR BACKUP_ENV AGE_RECIPIENT_FILE\n' "$0" >&2
    exit 64
fi

readonly BUNDLE_DIR=$1
readonly BACKUP_ENV=$2
readonly RECIPIENT_SOURCE=$3
readonly TARGET_BIN=/opt/plntir/bin/plntir-control-plane-backup
readonly TARGET_ENV=/etc/plntir/control-plane-backup.env
readonly TARGET_RECIPIENT=/etc/plntir/control-plane-backup-recipient.txt
readonly TARGET_SERVICE=/etc/systemd/system/plntir-control-plane-backup.service
readonly TARGET_TIMER=/etc/systemd/system/plntir-control-plane-backup.timer

for source in \
    "${BUNDLE_DIR}/control-node/bin/plntir-control-plane-backup" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.service" \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.timer" \
    "${BACKUP_ENV}" \
    "${RECIPIENT_SOURCE}"; do
    [[ -f ${source} && ! -L ${source} ]] || {
        printf 'Missing or unsafe backup input: %s\n' "${source}" >&2
        exit 66
    }
done
for tool in /usr/bin/age /usr/bin/curl; do
    [[ -x ${tool} ]] || {
        printf 'Install the Debian age and curl packages before provisioning.\n' >&2
        exit 69
    }
done

stamp=$(/bin/date -u +%Y%m%dT%H%M%SZ)
readonly stamp
backup_dir=/var/backups/plntir/${stamp}-offhost-backup
readonly backup_dir
/usr/bin/install -d -m 0700 "${backup_dir}"
for target in \
    "${TARGET_BIN}" "${TARGET_ENV}" "${TARGET_RECIPIENT}" \
    "${TARGET_SERVICE}" "${TARGET_TIMER}"; do
    if [[ -e ${target} ]]; then
        /bin/cp -a "${target}" "${backup_dir}/$(/usr/bin/basename "${target}").before"
    fi
done

/usr/bin/install -d -o root -g plntircontrol -m 0750 /opt/plntir/bin /etc/plntir
/usr/bin/install -d -o root -g root -m 0700 /var/lib/plntir/backup
/usr/bin/install -o root -g plntircontrol -m 0750 \
    "${BUNDLE_DIR}/control-node/bin/plntir-control-plane-backup" "${TARGET_BIN}"
/usr/bin/install -o root -g root -m 0600 "${BACKUP_ENV}" "${TARGET_ENV}"
/usr/bin/install -o root -g root -m 0644 "${RECIPIENT_SOURCE}" "${TARGET_RECIPIENT}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.service" \
    "${TARGET_SERVICE}"
/usr/bin/install -o root -g root -m 0644 \
    "${BUNDLE_DIR}/control-node/systemd/plntir-control-plane-backup.timer" \
    "${TARGET_TIMER}"

"${TARGET_BIN}" --validate-config
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl start plntir-control-plane-backup.service
/usr/bin/systemctl enable --now plntir-control-plane-backup.timer
/usr/bin/systemctl is-active --quiet plntir-control-plane-backup.timer
/usr/bin/jq -e '.state == "complete" and .stage == "verified-upload"' \
    /var/lib/plntir/backup/status.json >/dev/null

printf 'Plntir off-host backup installed and first R2 snapshot verified.\n'
printf 'Rollback evidence: %s\n' "${backup_dir}"
