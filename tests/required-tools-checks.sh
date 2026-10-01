#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tool_test_tmp=$(mktemp -d)
trap 'rm -rf -- "$tool_test_tmp"' EXIT

# A missing scanner must not be mistaken for a clean scan.
for check_script in static-checks.sh package-build-checks.sh; do
    if PATH="$tool_test_tmp" /bin/bash "$repo_root/tests/$check_script" >"$tool_test_tmp/output" 2>&1; then
        printf 'FAIL: %s passed without the required rg command.\n' "$check_script" >&2
        exit 1
    fi
    if ! grep -Fxq 'Missing required tool: rg (ripgrep) must be available in PATH.' "$tool_test_tmp/output"; then
        cat "$tool_test_tmp/output" >&2
        printf 'FAIL: %s did not report the missing scanner explicitly.\n' "$check_script" >&2
        exit 1
    fi
done
printf 'PASS: static and package checks fail explicitly when ripgrep is missing.\n'
