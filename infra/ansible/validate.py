#!/usr/bin/env python3
"""offline structural checks for the fail-closed plntir ansible root."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import subprocess
import tempfile
from typing import Any

import jinja2
import yaml


ROOT = pathlib.Path(__file__).resolve().parent
EXPECTED_HOSTS = {
    "plntir-core-01",
    "plntir-mdm-01",
    "plntir-edge-01",
    "plntir-relay-01",
    "plntir-siem-01",
}
WATCH_ARN = "arn:aws:lightsail:eu-central-1:444455556666:Instance/e40d6806-5f0b-4cfd-8ee9-36ac8f5af13d"


def load_yaml(path: pathlib.Path) -> Any:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value is None:
        raise AssertionError(f"empty YAML document: {path}")
    return value


def inventory_hosts(group: Any) -> set[str]:
    if not isinstance(group, dict):
        return set()
    result: set[str] = set()
    hosts = group.get("hosts", {})
    if isinstance(hosts, dict):
        result.update(hosts)
    children = group.get("children", {})
    if isinstance(children, dict):
        for child in children.values():
            result.update(inventory_hosts(child))
    return result


def render_firewall() -> str:
    template_path = ROOT / "roles/baseline/templates/plntir-filter.nft.j2"
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_path.parent),
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    template = environment.get_template(template_path.name)
    rendered = template.render(
        plntir_input_tcp_rules=[
            {
                "name": "short-lived-ssh-certificates",
                "port": 22,
                "ipv4_sources": ["10.0.0.10", "100.101.0.2"],
                "ipv6_sources": ["fd00::10"],
            }
        ],
        plntir_docker_tcp_rules=[
            {
                "name": "fleet-device-ingress",
                "published_port": 1338,
                "translated_port": 8080,
                "ipv4_sources": ["10.0.0.10"],
                "ipv6_sources": ["fd00::10"],
            }
        ],
        plntir_docker_internal_interfaces=["plntir-mdm-be", "plntir-mdm-dev"],
        plntir_docker_egress_interfaces=["plntir-mdm-eg"],
        plntir_external_interfaces=["eth0"],
        plntir_output_policy="drop",
        plntir_output_tcp_rules=[
            {
                "name": "relay-egress-proxy",
                "port": 3128,
                "ipv4_destinations": ["10.0.0.20"],
                "ipv6_destinations": [],
            },
            {
                "name": "relay-smtp-alerts",
                "port": 2525,
                "ipv4_destinations": ["10.0.0.20"],
                "ipv6_destinations": [],
            },
        ],
        plntir_output_udp_rules=[
            {
                "name": "relay-time-sync",
                "port": 123,
                "ipv4_destinations": ["10.0.0.20"],
                "ipv6_destinations": [],
            }
        ],
    )
    assert "policy drop" in rendered
    assert rendered.count("policy drop") == 3
    assert "0.0.0.0/0" not in rendered and "::/0" not in rendered
    assert "flush ruleset" not in rendered
    assert "ct original proto-dst 1338" in rendered
    assert 'iifname "br-*" accept' not in rendered
    assert 'iifname "docker0" accept' not in rendered
    assert 'iifname "plntir-mdm-be" oifname "plntir-mdm-be" accept' in rendered
    assert 'iifname "plntir-mdm-dev" oifname "plntir-mdm-dev" accept' in rendered
    assert 'iifname "plntir-mdm-eg" oifname "eth0" accept' in rendered
    assert 'iifname "plntir-mdm-be" oifname "eth0" accept' not in rendered
    assert "chain output" in rendered and "policy drop" in rendered
    assert "ip daddr { 10.0.0.20 } tcp dport 3128 accept" in rendered
    assert "ip daddr { 10.0.0.20 } tcp dport 2525 accept" in rendered
    assert "ip daddr { 10.0.0.20 } udp dport 123 accept" in rendered
    assert "{{" not in rendered and "{%" not in rendered
    return rendered


def optionally_check_nft(rendered: str) -> str:
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            result = subprocess.run(
                ["nft", "--check", "--file", handle.name],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
    except FileNotFoundError:
        return "SKIP nft syntax (nft not installed)"
    if result.returncode == 0:
        return "PASS nft syntax"
    if "Operation not permitted" in result.stderr or "netlink" in result.stderr.lower():
        return "SKIP nft syntax (unprivileged netlink)"
    raise AssertionError(f"nft rejected rendered policy: {result.stderr.strip()}")


def main() -> int:
    yaml_paths = sorted(ROOT.rglob("*.yml"))
    documents = {path: load_yaml(path) for path in yaml_paths}

    deny_inventory = documents[ROOT / "inventory/deny-all.yml"]
    assert inventory_hosts(deny_inventory["all"]) == set(), "default inventory is not empty"

    example_inventory = documents[ROOT / "inventory/hosts.example.yml"]
    assert inventory_hosts(example_inventory["all"]) == EXPECTED_HOSTS
    assert "watch" not in " ".join(inventory_hosts(example_inventory["all"])).lower()

    all_vars = documents[ROOT / "group_vars/all.yml"]
    assert all_vars["plntir_deployment_authorized"] is False
    assert all_vars["plntir_check_mode_authorized"] is False
    assert all_vars["plntir_immediate_approval_reference"] == ""
    assert all_vars["plntir_release_id"] == ""
    assert all_vars["plntir_forbidden_watch_arn"] == WATCH_ARN
    assert all_vars["plntir_output_policy"] == "accept"
    assert all_vars["plntir_output_tcp_rules"] == []
    assert all_vars["plntir_output_udp_rules"] == []

    roles = {
        documents[ROOT / f"group_vars/{name}.yml"]["plntir_node_role"]
        for name in ("core", "mdm", "edge", "relay", "siem")
    }
    assert roles == {"core", "mdm", "edge", "relay", "siem"}
    mdm = documents[ROOT / "group_vars/mdm.yml"]
    assert mdm["plntir_enable_docker"] is True
    assert {rule["published_port"] for rule in mdm["plntir_docker_tcp_rules"]} == {1337, 1338}
    assert mdm["plntir_docker_internal_interfaces"] == ["plntir-mdm-be", "plntir-mdm-dev"]
    assert mdm["plntir_docker_egress_interfaces"] == ["plntir-mdm-eg"]
    example_mdm = example_inventory["all"]["children"]["plntir_v1"]["children"]["mdm"]["hosts"]["plntir-mdm-01"]
    assert example_mdm["plntir_external_interfaces"] == ["REPLACE_MDM_PRIMARY_INTERFACE"]
    siem = documents[ROOT / "group_vars/siem.yml"]
    assert 1515 not in {rule["port"] for rule in siem["plntir_input_tcp_rules"]}
    assert 55000 not in {rule["port"] for rule in siem["plntir_input_tcp_rules"]}
    assert 9200 not in {rule["port"] for rule in siem["plntir_input_tcp_rules"]}
    assert siem["plntir_output_policy"] == "drop"
    assert {rule["port"] for rule in siem["plntir_output_tcp_rules"]} == {2525, 3128}
    assert {rule["port"] for rule in siem["plntir_output_udp_rules"]} == {123}
    assert siem["plntir_wazuh_enabled"] is False
    assert siem["plntir_wazuh_check_mode_authorized"] is False
    assert siem["plntir_wazuh_install_authorized"] is False
    assert siem["plntir_wazuh_release_version"] == "4.14.7"
    assert siem["plntir_wazuh_integrity_runtime_sha256"] == ""
    assert siem["plntir_wazuh_ingest_qualification_sha256"] == ""
    assert siem["plntir_wazuh_alert_routes_qualified"] is False
    assert siem["plntir_wazuh_rolesanywhere_qualified"] is False
    assert siem["plntir_wazuh_enrollment_window_authorized"] is False

    site = (ROOT / "site.yml").read_text(encoding="utf-8")
    gate_position = site.index("Require an immediate check or deployment gate")
    facts_position = site.index("Gather facts only after the gate")
    assert gate_position < facts_position
    for sentinel in ("gather_facts: false", "serial: 1", "any_errors_fatal: true", WATCH_ARN.split(":")[-1]):
        if sentinel == WATCH_ARN.split(":")[-1]:
            assert "plntir_forbidden_watch_arn" in site
        else:
            assert sentinel in site

    ssh = (ROOT / "roles/baseline/templates/90-plntir-sshd.conf.j2").read_text(encoding="utf-8")
    for required in (
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "DisableForwarding yes",
        "AuthenticationMethods publickey",
    ):
        assert required in ssh
    assert "PermitRootLogin yes" not in ssh and "PasswordAuthentication yes" not in ssh

    nft_template = (ROOT / "roles/baseline/templates/plntir-filter.nft.j2").read_text(encoding="utf-8")
    assert "policy drop" in nft_template
    assert "0.0.0.0/0" not in nft_template and "::/0" not in nft_template
    assert "tcp dport 1515" not in nft_template
    assert 'iifname "br-*" accept' not in nft_template
    rendered = render_firewall()

    baseline_tasks = (ROOT / "roles/baseline/tasks/main.yml").read_text(encoding="utf-8")
    policy_position = baseline_tasks.index("Install exact-source nftables policy")
    include_position = baseline_tasks.index("Install a non-destructive nftables include root")
    assert policy_position < include_position
    nft_root = (ROOT / "roles/baseline/templates/nftables.conf.j2").read_text(encoding="utf-8")
    assert 'include "/etc/nftables.d/90-plntir-filter.nft"' in nft_root

    wazuh_tasks = (ROOT / "roles/wazuh_isolated/tasks/main.yml").read_text(encoding="utf-8")
    for required in (
        "Enforce the independent Wazuh installation gate",
        "--offline-installation",
        "plntir_wazuh_release_attestation_sha256",
        "plntir_wazuh_prerequisites_qualification_sha256",
        "plntir_wazuh_integrity_runtime_sha256",
        "plntir_wazuh_ingest_qualification_sha256",
        "plntir_wazuh_alert_routes_qualified",
        "plntir_wazuh_rolesanywhere_qualified",
        "no_log: true",
    ):
        assert required in wazuh_tasks
    assert "apt_repository" not in wazuh_tasks
    assert "tcp dport 1515 accept" not in wazuh_tasks

    docker_template = ROOT / "roles/baseline/templates/docker-daemon.json.j2"
    docker_policy = json.loads(docker_template.read_text(encoding="utf-8"))
    assert docker_policy["icc"] is False
    assert docker_policy["no-new-privileges"] is True
    assert docker_policy["userland-proxy"] is False

    for address in ("10.0.0.10", "100.101.0.2", "fd00::10"):
        ipaddress.ip_address(address)

    deployable_paths = yaml_paths + [ROOT / "ansible.cfg"] + sorted((ROOT / "roles").rglob("*.j2"))
    joined = "\n".join(path.read_text(encoding="utf-8") for path in deployable_paths)
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "AKIA",
        "0.0.0.0/0",
        "::/0",
        "flush ruleset",
    ):
        assert forbidden not in joined, f"forbidden Ansible content: {forbidden}"

    print(f"PASS Ansible YAML: {len(yaml_paths)} documents")
    print("PASS empty default inventory and protected Watch exclusion")
    print("PASS exact-source input/forward policy and SSH baseline")
    print(optionally_check_nft(rendered))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
