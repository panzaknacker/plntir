#!/usr/bin/env python3
"""fail closed on security-sensitive plntir public API contract drift."""

from __future__ import annotations

import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "api" / "openapi.yaml"
UNSAFE_METHODS = {"post", "put", "patch", "delete"}
REQUIRED_GUARDS = {"IdempotencyKey", "CSRFToken"}
VERSION_GUARDS = {"ResourceVersion", "CreateOnlyVersion"}


def reference_name(parameter: object) -> str | None:
    if not isinstance(parameter, dict):
        return None
    reference = parameter.get("$ref")
    if not isinstance(reference, str):
        return None
    prefix = "#/components/parameters/"
    return reference.removeprefix(prefix) if reference.startswith(prefix) else None


def main() -> int:
    document = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    operation_ids: set[str] = set()

    if document.get("openapi") != "3.1.0":
        failures.append("contract must remain OpenAPI 3.1.0")

    paths = document.get("paths")
    if not isinstance(paths, dict):
        failures.append("paths must be a mapping")
        paths = {}

    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            failures.append(f"invalid path item: {path!r}")
            continue
        lowered_path = path.casefold()
        if "shell" in lowered_path or "terminal" in lowered_path:
            failures.append(f"forbidden arbitrary-execution route: {path}")

        for method, operation in path_item.items():
            if method not in {"get", "head", "options", *UNSAFE_METHODS}:
                continue
            if not isinstance(operation, dict):
                failures.append(f"{method.upper()} {path}: operation must be a mapping")
                continue

            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                failures.append(f"{method.upper()} {path}: missing operationId")
            elif operation_id in operation_ids:
                failures.append(f"duplicate operationId: {operation_id}")
            else:
                operation_ids.add(operation_id)

            if method not in UNSAFE_METHODS:
                continue
            references = {name for name in map(reference_name, operation.get("parameters", [])) if name is not None}
            missing = REQUIRED_GUARDS - references
            if missing:
                failures.append(f"{method.upper()} {path}: missing mutation guards {sorted(missing)}")
            versions = VERSION_GUARDS & references
            if len(versions) != 1:
                failures.append(f"{method.upper()} {path}: require exactly one version precondition")

    wipe_paths = [path for path in paths if path.endswith("/wipe")]
    if wipe_paths != ["/admin/devices/{deviceId}/wipe"]:
        failures.append("the contract must expose exactly one single-device wipe path")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(f"PASS OpenAPI mutation guards ({len(operation_ids)} operations)")
    print("PASS no shell, terminal, or bulk-wipe route")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
