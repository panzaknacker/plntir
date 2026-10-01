#!/usr/bin/env python3
"""black-box tests for the signed wazuh offline-release verifier."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
VERIFIER = ROOT / "infra/ansible/roles/wazuh_isolated/files/verify-release.py"


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        if not pathlib.Path("/usr/bin/openssl").exists():
            self.skipTest("/usr/bin/openssl is unavailable")
        self.temp = pathlib.Path(tempfile.mkdtemp(prefix="plntir-wazuh-release-test-"))
        self.addCleanup(shutil.rmtree, self.temp)
        self.artifacts = self.temp / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        contents = {
            "wazuh-install.sh": b"#!/bin/sh\nexit 0\n",
            "wazuh-offline.tar.gz": b"mock-offline-bundle",
            "wazuh-install-files.tar": b"mock-generated-secrets",
        }
        for name, content in contents.items():
            (self.artifacts / name).write_bytes(content)
        self.private_key = self.temp / "private.key"
        self.public_key = self.temp / "public.pem"
        subprocess.run(
            ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", self.private_key],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with self.public_key.open("wb") as output:
            subprocess.run(
                ["/usr/bin/openssl", "pkey", "-in", self.private_key, "-pubout"],
                check=True,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
        entries = []
        for name in sorted(contents):
            content = (self.artifacts / name).read_bytes()
            entries.append({"bytes": len(content), "name": name, "sha256": hashlib.sha256(content).hexdigest()})
        self.value = {
            "architecture": "amd64",
            "artifacts": entries,
            "created_at": "2026-09-04T12:00:00Z",
            "product": "plntir-wazuh-offline",
            "schema_version": 1,
            "version": "4.14.7",
        }
        self.manifest = self.temp / "release-manifest.json"
        self.signature = self.temp / "release-manifest.sig"
        self.write_manifest(canonical=True)

    def write_manifest(self, *, canonical: bool) -> None:
        if canonical:
            raw = (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        else:
            raw = json.dumps(self.value, indent=2, sort_keys=True).encode()
        self.manifest.write_bytes(raw)
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                self.private_key,
                "-rawin",
                "-in",
                self.manifest,
                "-out",
                self.signature,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def run_verifier(self, *, public_key: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
        raw = self.manifest.read_bytes()
        bundle = (self.artifacts / "wazuh-offline.tar.gz").read_bytes()
        return subprocess.run(
            [
                "/usr/bin/python3",
                VERIFIER,
                "--manifest",
                self.manifest,
                "--signature",
                self.signature,
                "--public-key",
                public_key or self.public_key,
                "--artifact-root",
                self.artifacts,
                "--expected-version",
                "4.14.7",
                "--expected-manifest-sha256",
                hashlib.sha256(raw).hexdigest(),
                "--expected-bundle-sha256",
                hashlib.sha256(bundle).hexdigest(),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_accepts_exact_signed_release(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "PASS signed Wazuh 4.14.7 amd64 offline release\n")

    def test_rejects_tampered_bundle(self) -> None:
        with (self.artifacts / "wazuh-offline.tar.gz").open("ab") as handle:
            handle.write(b"tamper")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact content does not match", result.stderr)

    def test_rejects_noncanonical_manifest_even_when_resigned(self) -> None:
        self.write_manifest(canonical=False)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest is not canonical", result.stderr)

    def test_rejects_private_signing_key(self) -> None:
        result = self.run_verifier(public_key=self.private_key)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public PEM key", result.stderr)

    def test_rejects_symlinked_artifact(self) -> None:
        target = self.artifacts / "wazuh-install.sh"
        saved = self.temp / "installer.saved"
        target.rename(saved)
        target.symlink_to(saved)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular non-symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
