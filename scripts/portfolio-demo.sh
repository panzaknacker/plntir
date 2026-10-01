#!/usr/bin/env bash
# Run the archive round-trip and tamper test without deployment or downloads.
set -euo pipefail

if [[ $# -ne 0 ]]; then
    printf 'Usage: bash scripts/portfolio-demo.sh\n' >&2
    exit 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo_root"
for required_tool in go mktemp sha256sum tee grep; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
        printf 'Missing local tool: %s. See docs/DEMO.md.\n' "$required_tool" >&2
        exit 1
    fi
done

demo_tmp=$(mktemp -d "${TMPDIR:-/tmp}/plntir-portfolio.XXXXXX")
trap 'rm -rf -- "$demo_tmp"' EXIT
export TMPDIR="$demo_tmp"
export GOCACHE="${GOCACHE:-$demo_tmp/build-cache}"
export GOPROXY=off
export GOSUMDB=off
export GOTOOLCHAIN=local
export GOWORK=off
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0
export LC_ALL=C

printf 'Plntir local archive example\n'
printf 'Scope: existing archive regression test; synthetic data and local mocks.\n'
go version
source_fingerprint=$(sha256sum scripts/portfolio-demo.sh mac/archive-agent/go.mod \
    mac/archive-agent/go.sum mac/archive-agent/archive/*.go | sha256sum)
printf 'Demo source fingerprint (SHA-256): %s\n' "${source_fingerprint%% *}"
printf 'Downloads: disabled. Device and cloud configuration: not loaded.\n\n'
printf 'Running: archive creation, exact restore, then ciphertext tamper rejection.\n'

cd -- mac/archive-agent
if ! go test -count=1 -v ./archive -run '^TestFullFileRestoreUsesOnlyOfflinePrivateKey$' 2>&1 | tee "$demo_tmp/test.log"; then
    printf '\nExample failed. Check the compiler/test error above and docs/DEMO.md.\n' >&2
    exit 1
fi
if ! grep -q '^--- PASS: TestFullFileRestoreUsesOnlyOfflinePrivateKey ' "$demo_tmp/test.log"; then
    printf '\nExample failed: the expected named test did not report a pass.\n' >&2
    exit 1
fi

printf '\nPASS: the existing restore/tamper test completed successfully.\n'
printf 'Boundary: local archive-library behavior; no cloud or macOS deployment tested.\n'
printf 'Temporary test data are removed on exit; a supplied GOCACHE is retained.\n'
