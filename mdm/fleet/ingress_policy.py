#!/usr/bin/env python3
"""validate and render plntir's exact fleet device-ingress contract."""

from __future__ import annotations

import argparse
import difflib
import json
import pathlib
import re
import sys
import urllib.parse
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_POLICY = ROOT / "public-routes-v4.89.2.json"
DEFAULT_CLOUDFLARED = ROOT / "cloudflared.example.yml"
EXPECTED_HOST = "mdm.plntir.example"
EXPECTED_TAG = "fleet-v4.89.2"
EXPECTED_ARCHIVE_SHA256 = "1fb267b8a0b997b201bc833e13794d773c3dd75b5117101345219b63e1ff27e9"
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT"}
PATH_RE = re.compile(r"/[A-Za-z0-9._/-]+\Z")
ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class PolicyError(ValueError):
    """the checked-in policy is unsafe or internally inconsistent."""


def load_policy(path: pathlib.Path = DEFAULT_POLICY) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError("policy root must be an object")
    validate_policy(value)
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{field} must be a non-empty string")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema_version") != 1:
        raise PolicyError("schema_version must be 1")
    if policy.get("hostname") != EXPECTED_HOST:
        raise PolicyError(f"hostname must be exactly {EXPECTED_HOST}")

    release = policy.get("release")
    if not isinstance(release, dict):
        raise PolicyError("release must be an object")
    if release.get("tag") != EXPECTED_TAG:
        raise PolicyError(f"release.tag must be exactly {EXPECTED_TAG}")
    if release.get("source_archive_sha256") != EXPECTED_ARCHIVE_SHA256:
        raise PolicyError("Fleet source archive SHA-256 differs from the reviewed release")
    image = _string(release.get("container_image"), "release.container_image")
    if not re.fullmatch(r"fleetdm/fleet:v4\.89\.2@sha256:[0-9a-f]{64}", image):
        raise PolicyError("Fleet container image must use the reviewed tag and digest")

    routes = policy.get("routes")
    if not isinstance(routes, list) or not routes:
        raise PolicyError("routes must be a non-empty array")
    ids: set[str] = set()
    paths: set[str] = set()
    for index, route in enumerate(routes):
        field = f"routes[{index}]"
        if not isinstance(route, dict):
            raise PolicyError(f"{field} must be an object")
        route_id = _string(route.get("id"), f"{field}.id")
        path = _string(route.get("path"), f"{field}.path")
        methods = route.get("methods")
        sources = route.get("sources")
        _string(route.get("purpose"), f"{field}.purpose")
        if not ID_RE.fullmatch(route_id) or route_id in ids:
            raise PolicyError(f"{field}.id is invalid or duplicated")
        if (
            not PATH_RE.fullmatch(path)
            or path == "/"
            or "//" in path
            or path.endswith("/")
            or any(part in {".", ".."} for part in path.split("/"))
            or path in paths
        ):
            raise PolicyError(f"{field}.path is non-canonical or duplicated")
        if (
            not isinstance(methods, list)
            or not methods
            or len(methods) != len(set(methods))
            or any(method not in ALLOWED_METHODS for method in methods)
        ):
            raise PolicyError(f"{field}.methods is invalid")
        if (
            not isinstance(sources, list)
            or not sources
            or any(not isinstance(source, str) or not source for source in sources)
        ):
            raise PolicyError(f"{field}.sources must identify reviewed Fleet source lines")
        ids.add(route_id)
        paths.add(path)

    excluded = policy.get("intentionally_excluded")
    if not isinstance(excluded, list) or not excluded:
        raise PolicyError("intentionally_excluded must document disabled feature families")
    for index, group in enumerate(excluded):
        if not isinstance(group, dict):
            raise PolicyError(f"intentionally_excluded[{index}] must be an object")
        _string(group.get("feature"), f"intentionally_excluded[{index}].feature")
        examples = group.get("examples")
        if not isinstance(examples, list) or not examples:
            raise PolicyError(f"intentionally_excluded[{index}].examples must not be empty")
        for example in examples:
            if not isinstance(example, str) or not example.startswith("/"):
                raise PolicyError("excluded route examples must be absolute paths")
            if example in paths:
                raise PolicyError(f"excluded path is also allowed: {example}")


def render_cloudflared(policy: dict[str, Any]) -> str:
    hostname = policy["hostname"]
    lines = [
        "# Code generated by mdm/fleet/ingress_policy.py; DO NOT EDIT.",
        "# The on-node ingress proxy enforces the methods recorded in the JSON policy.",
        "tunnel: REPLACE_TUNNEL_UUID",
        "credentials-file: /etc/cloudflared/REPLACE_TUNNEL_UUID.json",
        "",
        "originRequest:",
        f"  httpHostHeader: {hostname}",
        "  connectTimeout: 10s",
        "",
        "ingress:",
    ]
    for route in policy["routes"]:
        path = route["path"]
        lines.extend(
            [
                f"  # {route['id']}: {', '.join(route['methods'])}",
                f"  - hostname: {hostname}",
                f"    path: ^{re.escape(path)}$",
                "    service: http://REPLACE_MDM_PRIVATE_IP:1338",
            ]
        )
    lines.extend(
        [
            f"  - hostname: {hostname}",
            "    service: http_status:404",
            "  - service: http_status:404",
            "",
        ]
    )
    return "\n".join(lines)


def request_allowed(policy: dict[str, Any], method: str, raw_url: str, host: str) -> bool:
    method = method.upper()
    if host.lower() != policy["hostname"]:
        return False
    if any(char in raw_url for char in ("\r", "\n", "\\")):
        return False
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme or parsed.netloc or parsed.fragment or "%" in parsed.path:
        return False
    path = parsed.path
    if not PATH_RE.fullmatch(path) or "//" in path or path.endswith("/"):
        return False
    return any(route["path"] == path and method in route["methods"] for route in policy["routes"])


def check_generated(policy: dict[str, Any], path: pathlib.Path) -> bool:
    expected = render_cloudflared(policy)
    try:
        actual = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return False
    if actual == expected:
        return True
    diff = difflib.unified_diff(
        actual.splitlines(),
        expected.splitlines(),
        fromfile=str(path),
        tofile="rendered policy",
        lineterm="",
    )
    print("\n".join(diff), file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=pathlib.Path, default=DEFAULT_POLICY)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true")
    action.add_argument("--render", action="store_true")
    action.add_argument("--match", nargs=2, metavar=("METHOD", "URL"))
    parser.add_argument("--host", default=EXPECTED_HOST)
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"invalid Fleet ingress policy: {exc}", file=sys.stderr)
        return 1
    if args.render:
        sys.stdout.write(render_cloudflared(policy))
        return 0
    if args.match:
        allowed = request_allowed(policy, args.match[0], args.match[1], args.host)
        print("allow" if allowed else "deny")
        return 0 if allowed else 1
    if not check_generated(policy, DEFAULT_CLOUDFLARED):
        return 1
    print(f"Fleet ingress policy valid: {len(policy['routes'])} exact routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
