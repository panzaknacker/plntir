#!/usr/bin/env python3
"""verify a signed, canonical plntir wazuh offline-release manifest."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


EXPECTED_NAMES = {
    "wazuh-install.sh",
    "wazuh-offline.tar.gz",
    "wazuh-install-files.tar",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CREATED_AT_RE = re.compile(
    r"^20[0-9]{2}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


class VerificationError(Exception):
    """a bounded, user-facing release verification failure."""


def sha256_file(path: pathlib.Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("manifest contains a duplicate object key")
        result[key] = value
    return result


def regular_file_size(path: pathlib.Path, limit: int, label: str) -> int:
    try:
        stat = path.lstat()
    except OSError as error:
        raise VerificationError(f"{label} is unavailable") from error
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{label} must be a regular non-symlink file")
    if stat.st_size <= 0 or stat.st_size > limit:
        raise VerificationError(f"{label} has an invalid size")
    return stat.st_size


def read_bounded(path: pathlib.Path, limit: int, label: str) -> bytes:
    regular_file_size(path, limit, label)
    return path.read_bytes()


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise VerificationError(f"{label} has unknown or missing fields")


def parse_manifest(raw: bytes, expected_version: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("manifest is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise VerificationError("manifest root must be an object")
    require_exact_keys(
        value,
        {
            "architecture",
            "artifacts",
            "created_at",
            "product",
            "schema_version",
            "version",
        },
        "manifest",
    )
    canonical = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if raw != canonical:
        raise VerificationError("manifest is not canonical JSON with one final newline")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != 1:
        raise VerificationError("unsupported manifest schema")
    if not isinstance(value["product"], str) or value["product"] != "plntir-wazuh-offline":
        raise VerificationError("unexpected manifest product")
    if not isinstance(value["version"], str) or value["version"] != expected_version or expected_version != "4.14.7":
        raise VerificationError("Wazuh release is not exactly 4.14.7")
    if not isinstance(value["architecture"], str) or value["architecture"] != "amd64":
        raise VerificationError("Wazuh offline release is not amd64")
    if not isinstance(value["created_at"], str) or not CREATED_AT_RE.fullmatch(value["created_at"]):
        raise VerificationError("created_at is not an RFC3339 UTC second")
    try:
        datetime.datetime.strptime(value["created_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise VerificationError("created_at is not a real UTC calendar time") from error
    if not isinstance(value["artifacts"], list) or len(value["artifacts"]) != 3:
        raise VerificationError("manifest must bind exactly three artifacts")
    return value


def validate_artifacts(manifest: dict[str, Any], artifact_root: pathlib.Path, expected_bundle_sha256: str) -> None:
    if artifact_root.is_symlink() or not artifact_root.is_dir():
        raise VerificationError("artifact root must be a regular directory")
    observed: set[str] = set()
    for entry in manifest["artifacts"]:
        if not isinstance(entry, dict):
            raise VerificationError("artifact entry must be an object")
        require_exact_keys(entry, {"bytes", "name", "sha256"}, "artifact entry")
        name = entry["name"]
        digest = entry["sha256"]
        size = entry["bytes"]
        if not isinstance(name, str) or name not in EXPECTED_NAMES or name in observed:
            raise VerificationError("artifact name is unexpected or duplicated")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise VerificationError("artifact SHA-256 is malformed")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= 10**11:
            raise VerificationError("artifact size is invalid")
        path = artifact_root / name
        regular_file_size(path, 10**11, f"artifact {name}")
        actual_digest, actual_size = sha256_file(path)
        if actual_digest != digest or actual_size != size:
            raise VerificationError("artifact content does not match the manifest")
        if name == "wazuh-offline.tar.gz" and digest != expected_bundle_sha256:
            raise VerificationError("offline bundle does not match the approved digest")
        observed.add(name)
    if observed != EXPECTED_NAMES:
        raise VerificationError("release does not contain the exact artifact set")


def verify_signature(
    manifest: bytes,
    signature_path: pathlib.Path,
    public_key_path: pathlib.Path,
) -> None:
    public_key = read_bounded(public_key_path, 8192, "release public key")
    if b"PRIVATE KEY" in public_key or b"BEGIN PUBLIC KEY" not in public_key:
        raise VerificationError("release key must be a public PEM key")
    if regular_file_size(signature_path, 1024, "release signature") != 64:
        raise VerificationError("release signature is not an Ed25519 signature")
    try:
        key_result = subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-pubin",
                "-in",
                os.fspath(public_key_path),
                "-text_pub",
                "-noout",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=15,
            check=False,
        )
        if key_result.returncode != 0 or b"ED25519 Public-Key" not in key_result.stdout:
            raise VerificationError("release key is not a valid Ed25519 public key")
        with tempfile.NamedTemporaryFile(prefix=".plntir-wazuh-manifest-") as verified_input:
            os.chmod(verified_input.name, 0o600)
            verified_input.write(manifest)
            verified_input.flush()
            os.fsync(verified_input.fileno())
            result = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    os.fspath(public_key_path),
                    "-sigfile",
                    os.fspath(signature_path),
                    "-rawin",
                    "-in",
                    verified_input.name,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=15,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("OpenSSL signature verification could not run") from error
    if result.returncode != 0:
        raise VerificationError("release signature is invalid")


def verify(args: argparse.Namespace) -> None:
    if args.expected_version != "4.14.7":
        raise VerificationError("expected version must be exactly 4.14.7")
    for digest in (args.expected_manifest_sha256, args.expected_bundle_sha256):
        if not SHA256_RE.fullmatch(digest):
            raise VerificationError("an expected SHA-256 is malformed")
    manifest_path = pathlib.Path(args.manifest)
    signature_path = pathlib.Path(args.signature)
    public_key_path = pathlib.Path(args.public_key)
    artifact_root = pathlib.Path(args.artifact_root)
    raw = read_bounded(manifest_path, 65536, "release manifest")
    if hashlib.sha256(raw).hexdigest() != args.expected_manifest_sha256:
        raise VerificationError("manifest does not match the approved digest")
    manifest = parse_manifest(raw, args.expected_version)
    validate_artifacts(manifest, artifact_root, args.expected_bundle_sha256)
    verify_signature(raw, signature_path, public_key_path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--manifest", required=True)
    result.add_argument("--signature", required=True)
    result.add_argument("--public-key", required=True)
    result.add_argument("--artifact-root", required=True)
    result.add_argument("--expected-version", required=True)
    result.add_argument("--expected-manifest-sha256", required=True)
    result.add_argument("--expected-bundle-sha256", required=True)
    return result


def main() -> int:
    try:
        verify(parser().parse_args())
    except VerificationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS signed Wazuh 4.14.7 amd64 offline release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
