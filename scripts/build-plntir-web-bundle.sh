#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
OUTPUT_PARENT=$(cd "$(dirname "$1")" && pwd -P)
readonly OUTPUT_PARENT
OUTPUT=${OUTPUT_PARENT}/$(basename "$1")
readonly OUTPUT
GO_BINARY=$(command -v go || true)
readonly GO_BINARY
[[ -n ${GO_BINARY} && -x ${GO_BINARY} ]] || {
    printf 'Go compiler not found in PATH.\n' >&2
    exit 69
}
[[ ! -e ${OUTPUT} && ! -L ${OUTPUT} ]] || {
    printf 'Refusing existing bundle directory: %s\n' "${OUTPUT}" >&2
    exit 73
}

/usr/bin/install -d -m 0700 \
    "${OUTPUT}/bin" \
    "${OUTPUT}/client/internal/collector" \
    "${OUTPUT}/control-node/bin" \
    "${OUTPUT}/control-node/sudoers" \
    "${OUTPUT}/control-node/systemd" \
    "${OUTPUT}/config/nftables" \
    "${OUTPUT}/scripts"

(cd "${ROOT}/client" &&
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BINARY}" build \
        -buildvcs=false -trimpath -ldflags '-s -w' \
        -o "${OUTPUT}/bin/plntir-web" ./cmd/plntir-web)

/usr/bin/install -m 0755 \
    "${ROOT}/control-node/bin/plntir-control-plane-backup" \
    "${ROOT}/control-node/bin/plntir-endpoint-retrieve" \
    "${ROOT}/control-node/bin/plntir-web-action" \
    "${OUTPUT}/control-node/bin/"
/usr/bin/install -m 0755 \
    "${ROOT}/client/internal/collector/plntir-status-v2.sh" \
    "${OUTPUT}/client/internal/collector/"
/usr/bin/install -m 0440 \
    "${ROOT}/control-node/sudoers/91-plntir-web" \
    "${OUTPUT}/control-node/sudoers/"
/usr/bin/install -m 0644 \
    "${ROOT}/control-node/systemd/plntir-web.service" \
    "${OUTPUT}/control-node/systemd/"
/usr/bin/install -m 0755 \
    "${ROOT}/scripts/install-plntir-web-dashboard.sh" \
    "${ROOT}/scripts/verify-plntir-web-dashboard.sh" \
    "${OUTPUT}/scripts/"
/usr/bin/install -m 0644 \
    "${ROOT}/config/nftables/nftables.conf" \
    "${OUTPUT}/config/nftables/"

(
    cd "${OUTPUT}"
    /usr/bin/sha256sum \
        bin/plntir-web \
        client/internal/collector/plntir-status-v2.sh \
        control-node/bin/plntir-control-plane-backup \
        control-node/bin/plntir-endpoint-retrieve \
        control-node/bin/plntir-web-action \
        control-node/sudoers/91-plntir-web \
        control-node/systemd/plntir-web.service \
        scripts/install-plntir-web-dashboard.sh \
        scripts/verify-plntir-web-dashboard.sh \
        config/nftables/nftables.conf \
        >SHA256SUMS
)
/bin/chmod 0644 "${OUTPUT}/SHA256SUMS"
printf 'Plntir web bundle: %s\n' "${OUTPUT}"
