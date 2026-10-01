#!/usr/bin/env python3
"""Exercise the deployed readiness guards without invoking systemctl."""

from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "scripts/activate-plntir-secure-access.sh": ("timer",),
    "scripts/provision-plntir-control-node.sh": ("timer", "service"),
}
STATES = (
    ("loaded/inactive", "LoadState=loaded\nActiveState=inactive\n", 0, 0),
    ("reversed property order", "ActiveState=inactive\nLoadState=loaded\n", 0, 0),
    *(
        (state, f"LoadState=loaded\nActiveState={state}\n", 0, 77)
        for state in (
            "active",
            "activating",
            "deactivating",
            "failed",
            "reloading",
            "refreshing",
            "maintenance",
            "unknown",
        )
    ),
    *(
        (state, f"LoadState={state}\nActiveState=inactive\n", 0, 77)
        for state in ("not-found", "masked", "error", "stub", "bad-setting")
    ),
    ("missing properties", "", 0, 77),
    ("missing load state", "ActiveState=inactive\n", 0, 77),
    ("missing active state", "LoadState=loaded\n", 0, 77),
    ("duplicate properties", "LoadState=loaded\nLoadState=loaded\nActiveState=inactive\n", 0, 77),
    ("extra output", "LoadState=loaded\nActiveState=inactive\nunexpected\n", 0, 77),
    *((f"query error {status}", "LoadState=loaded\nActiveState=inactive\n", status, 77) for status in (1, 3, 4)),
)


def main() -> None:
    cases = 0
    for script, suffixes in SCRIPTS.items():
        source = (ROOT / script).read_text(encoding="utf-8")
        for suffix in suffixes:
            unit = f"plntir-secure-archive-readiness.{suffix}"
            command = f"show --property=LoadState --property=ActiveState -- {unit}"
            matches = re.findall(
                rf"^if ! readiness_{suffix}_state=\$\(/usr/bin/systemctl show .*?^esac$", source, re.M | re.S
            )
            if len(matches) != 1:
                raise RuntimeError(f"Expected an explicit inactive guard: {script}: {unit}")
            guard = matches[0].replace("/usr/bin/systemctl", "mock_systemctl")
            for label, output, status, expected in STATES:
                harness = (
                    "set -Eeuo pipefail\n"
                    "mock_systemctl() {\n"
                    f'    [[ "$*" == "{command}" ]] || exit 91\n'
                    f"    printf '%s' {shlex.quote(output)}\n"
                    f"    return {status}\n"
                    "}\n"
                    f"{guard}\n"
                    "printf 'continued\\n'\n"
                )
                result = subprocess.run(["/bin/bash", "-c", harness], capture_output=True, text=True, timeout=5)
                expected_stdout = "continued\n" if expected == 0 else ""
                if result.returncode != expected or result.stdout != expected_stdout:
                    raise RuntimeError(f"Guard failed: {script}: {unit}: {label}: {result}")
                cases += 1
    print(f"PASS: {cases} readiness guard cases; no services were queried or changed.")


if __name__ == "__main__":
    main()
