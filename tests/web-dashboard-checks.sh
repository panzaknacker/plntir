#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

workdir=$(/usr/bin/mktemp -d)
cleanup() {
    case ${workdir} in
    /tmp/* | /var/tmp/*) /bin/rm -rf "${workdir}" ;;
    *) printf 'Refusing unsafe dashboard test cleanup.\n' >&2 ;;
    esac
}
trap cleanup EXIT

python3 tests/web-dashboard-checks.py
if command -v node >/dev/null 2>&1; then
    node --check client/internal/webconsole/static/app.js
else
    printf 'SKIP node JavaScript syntax check (not installed)\n'
fi

for executable in \
    control-node/bin/plntir-web-action \
    scripts/build-plntir-web-bundle.sh \
    scripts/generate-plntir-web-auth.sh \
    scripts/generate-plntir-web-tls.sh \
    scripts/install-plntir-web-dashboard.sh \
    scripts/verify-plntir-web-dashboard.sh; do
    [[ -x ${executable} ]] || {
        printf 'Dashboard executable bit missing: %s\n' "${executable}" >&2
        exit 1
    }
done

if rg -n 'localStorage|sessionStorage|document[.]cookie|innerHTML|eval[(]' \
    client/internal/webconsole/static; then
    printf 'Unsafe browser-side persistence or DOM execution primitive found.\n' >&2
    exit 1
fi
grep -Fq 'server.requirePrivate(server.handleAudit)' client/internal/webconsole/server.go
grep -Fq 'server.requirePrivate(server.handleFilesPreview)' client/internal/webconsole/server.go
grep -Fq 'MAX_PREVIEW_BYTES = 512 * 1024' mac/libexec/plntir-retrieval-export.py.in
grep -Fq 'private_session_minutes:10' scripts/install-plntir-web-dashboard.sh
grep -Fq 'action_command:["/usr/bin/sudo","-n","-u","admin","/opt/plntir/bin/plntir-web-action"]' scripts/install-plntir-web-dashboard.sh
grep -Fq '[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$' scripts/install-plntir-web-dashboard.sh
printf '%s\n' \
    '{"schema_version":1,"username":"operator","password_hash":"pbkdf2-sha256$600000$A+/0$B+/1"}' |
    /usr/bin/jq -e \
        '.schema_version == 1 and (.username | test("^[A-Za-z0-9._-]{1,64}$")) and (.password_hash | test("^pbkdf2-sha256\\$[0-9]+\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$"))' \
        >/dev/null
grep -Fq '/usr/bin/systemctl restart plntir-web.service' scripts/install-plntir-web-dashboard.sh
grep -Fq 'for readiness_attempt in {1..20}; do' scripts/install-plntir-web-dashboard.sh
grep -Fq 'control-node/bin/plntir-endpoint-retrieve' scripts/build-plntir-web-bundle.sh
grep -Fq '"${BUNDLE}/control-node/bin/plntir-endpoint-retrieve" /opt/plntir/bin/plntir-endpoint-retrieve' scripts/install-plntir-web-dashboard.sh
grep -Fq "endpoint retrieval supports dashboard actions" scripts/verify-plntir-web-dashboard.sh
grep -Fq 'client/internal/collector/plntir-status-v2.sh' scripts/build-plntir-web-bundle.sh
grep -Fq 'control-node/bin/plntir-control-plane-backup' scripts/build-plntir-web-bundle.sh
grep -Fq 'control backup includes dashboard state' scripts/verify-plntir-web-dashboard.sh
if grep -Fq '/usr/bin/systemctl enable --now plntir-web.service' scripts/install-plntir-web-dashboard.sh; then
    printf 'Dashboard installer must restart the service before readiness checks.\n' >&2
    exit 1
fi
grep -Fq 'too many pending export jobs' client/internal/webconsole/jobs.go
grep -Fq 'if (state.statusRequest) return state.statusRequest;' client/internal/webconsole/static/app.js
grep -Fq 'renderStatusFailure(error);' client/internal/webconsole/static/app.js
grep -Fq 'timeoutMs: 40000' client/internal/webconsole/static/app.js
grep -Fq 'Export wirklich starten?' client/internal/webconsole/static/app.js
grep -Fq 'if (!privateActive() || !paths.length || state.exportSubmitting) return;' client/internal/webconsole/static/app.js
grep -Fq 'if (state.jobsRequest) return state.jobsRequest;' client/internal/webconsole/static/app.js
grep -Fq 'if (state.archivesRequest) return state.archivesRequest;' client/internal/webconsole/static/app.js
grep -Fq 'requestID !== state.filesRequestID' client/internal/webconsole/static/app.js
grep -Fq 'requestID !== state.previewRequestID' client/internal/webconsole/static/app.js
grep -Fq 'requestID !== state.safariRequestID' client/internal/webconsole/static/app.js
grep -Fq 'requestID !== state.auditRequestID' client/internal/webconsole/static/app.js
grep -Fq 'download.download = archive.name.split("/").pop()' client/internal/webconsole/static/app.js
grep -Fq 'window.setInterval(loadJobs, 5000)' client/internal/webconsole/static/app.js
grep -Fq 'void reloadArchivesAfterJob();' client/internal/webconsole/static/app.js
grep -Fq 'an identical export job is already pending' client/internal/webconsole/jobs.go
grep -Fq 'archive_bytes=$(printf' control-node/bin/plntir-endpoint-retrieve
grep -Fq 'minimum_reserve_kib=$((10 * 1024 * 1024))' control-node/bin/plntir-endpoint-retrieve
grep -Fq 'readonly EXPORT_BANDWIDTH_KBIT=25000' control-node/bin/plntir-endpoint-retrieve
grep -Fq 'scp -O -q -l "${EXPORT_BANDWIDTH_KBIT}"' control-node/bin/plntir-endpoint-retrieve
grep -Fq 'process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}' client/internal/webconsole/source.go
grep -Fq 'process.WaitDelay = 5 * time.Second' client/internal/webconsole/source.go
grep -Fq 'archive=$(/usr/bin/nice -n 10' control-node/bin/plntir-web-action
grep -Fq 'exec /usr/bin/nice -n 10 /usr/bin/scp -f' mac/libexec/plntir-response-dispatch.in
grep -Fq 'enabled|enabled-runtime' client/internal/collector/plntir-status-v2.sh
grep -Fq 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' control-node/systemd/plntir-web.service
if grep -Fxq 'CapabilityBoundingSet=' control-node/systemd/plntir-web.service; then
    printf 'Empty capability bounding set would break the fixed sudo broker.\n' >&2
    exit 1
fi

./scripts/build-plntir-web-bundle.sh "${workdir}/bundle" >/dev/null
(
    cd "${workdir}/bundle"
    /usr/bin/sha256sum --check --strict SHA256SUMS >/dev/null
    if /usr/bin/grep -Eq '  /|[.][.]/' SHA256SUMS; then
        printf 'Unsafe path found in dashboard checksum manifest.\n' >&2
        exit 1
    fi
)

printf 'Web dashboard checks passed.\n'
