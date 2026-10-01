#!/usr/bin/env python3
"""independent positive and negative checks for fleet's public route boundary."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "mdm" / "fleet" / "ingress_policy.py"
SPEC = importlib.util.spec_from_file_location("fleet_ingress_policy", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
POLICY_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY_MODULE)


class FleetIngressPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = POLICY_MODULE.load_policy()

    def test_exact_reviewed_route_set(self) -> None:
        actual = {(route["path"], method) for route in self.policy["routes"] for method in route["methods"]}
        expected = {
            ("/mdm/apple/scep", "GET"),
            ("/mdm/apple/scep", "POST"),
            ("/mdm/apple/mdm", "PUT"),
            ("/api/mdm/apple/installer", "GET"),
            ("/api/mdm/apple/installer", "HEAD"),
            ("/api/v1/osquery/enroll", "POST"),
            ("/api/v1/osquery/config", "POST"),
            ("/api/v1/osquery/distributed/read", "POST"),
            ("/api/v1/osquery/distributed/write", "POST"),
            ("/api/v1/osquery/log", "POST"),
            ("/api/fleet/orbit/enroll", "POST"),
            ("/api/fleet/orbit/ping", "HEAD"),
            ("/api/fleet/orbit/config", "POST"),
            ("/api/fleet/orbit/device_token", "POST"),
            ("/api/fleet/orbit/device_mapping", "PUT"),
            ("/api/fleet/orbit/scripts/request", "POST"),
            ("/api/fleet/orbit/scripts/result", "POST"),
        }
        self.assertEqual(actual, expected)

    def test_every_declared_route_and_query_is_allowed(self) -> None:
        for route in self.policy["routes"]:
            for method in route["methods"]:
                with self.subTest(route=route["id"], method=method):
                    self.assertTrue(
                        POLICY_MODULE.request_allowed(
                            self.policy,
                            method,
                            route["path"] + "?opaque=device-token",
                            "mdm.plntir.example",
                        )
                    )

    def test_interactive_and_disabled_feature_routes_are_denied(self) -> None:
        attempts = [
            ("GET", "/"),
            ("GET", "/login"),
            ("POST", "/api/v1/fleet/users"),
            ("GET", "/api/v1/fleet/hosts"),
            ("GET", "/api/mdm/apple/enroll?token=x"),
            ("POST", "/api/v1/fleet/ota_enrollment"),
            ("GET", "/mdm/apple/service_discovery"),
            ("HEAD", "/api/fleet/device/ping"),
            ("POST", "/api/fleet/orbit/software_install/package?alt=media"),
            ("POST", "/api/fleet/orbit/setup_experience/status"),
            ("POST", "/api/fleet/orbit/disk_encryption_key"),
            ("POST", "/api/v1/osquery/carve/begin"),
            ("POST", "/api/v1/osquery/carve/block"),
            ("POST", "/api/v1/osquery/yara/rules"),
        ]
        for method, target in attempts:
            with self.subTest(method=method, target=target):
                self.assertFalse(POLICY_MODULE.request_allowed(self.policy, method, target, "mdm.plntir.example"))

    def test_method_host_and_path_confusion_are_denied(self) -> None:
        attempts = [
            ("GET", "/api/fleet/orbit/config", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit/config", "admin.plntir.example"),
            ("POST", "/api/fleet/orbit/config", "mdm.plntir.example.example"),
            ("POST", "/api/fleet/orbit/config/", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit/config/extra", "mdm.plntir.example"),
            ("POST", "/x/api/fleet/orbit/config", "mdm.plntir.example"),
            ("POST", "/api/fleet//orbit/config", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit/../orbit/config", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit%2fconfig", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit/%63onfig", "mdm.plntir.example"),
            ("POST", "//mdm.plntir.example/api/fleet/orbit/config", "mdm.plntir.example"),
            ("POST", "/api/fleet/orbit\\config", "mdm.plntir.example"),
        ]
        for method, target, host in attempts:
            with self.subTest(method=method, target=target, host=host):
                self.assertFalse(POLICY_MODULE.request_allowed(self.policy, method, target, host))

    def test_cloudflared_file_is_generated_and_has_no_broad_rule(self) -> None:
        self.assertTrue(POLICY_MODULE.check_generated(self.policy, ROOT / "mdm" / "fleet" / "cloudflared.example.yml"))
        rendered = POLICY_MODULE.render_cloudflared(self.policy)
        for forbidden in (
            "/api/osquery/.*",
            "/api/v1/osquery/.*",
            "/api/fleet/orbit/.*",
            "fleet.plntir.example",
            "ops.plntir.example",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(rendered.count("service: http://REPLACE_MDM_PRIVATE_IP:1338"), 15)
        self.assertTrue(rendered.endswith("  - service: http_status:404\n"))

    def test_policy_mutations_fail_closed(self) -> None:
        mutations = [
            lambda value: value.update(hostname="mdm.plntir.example.example"),
            lambda value: value["release"].update(tag="fleet-v4.90.0"),
            lambda value: value["release"].update(source_archive_sha256="0" * 64),
            lambda value: value["routes"][0].update(path="/api/*"),
            lambda value: value["routes"][0].update(methods=["get"]),
            lambda value: value["routes"][1].update(path=value["routes"][0]["path"]),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(self.policy)
            mutate(changed)
            with self.assertRaises(POLICY_MODULE.PolicyError):
                POLICY_MODULE.validate_policy(changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
