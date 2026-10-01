locals {
  broker_enabled  = var.cloud_mutations_authorized && var.broker_stack_enabled
  compute_enabled = var.cloud_mutations_authorized && var.compute_stack_enabled
  wazuh_integrity_requested = (
    var.cloud_mutations_authorized && var.wazuh_integrity_stack_enabled
  )
  wazuh_integrity_enabled = (
    local.wazuh_integrity_requested &&
    var.wazuh_last_stage_approved &&
    var.wazuh_siem_qualification_sha256 != "" &&
    var.wazuh_offline_bundle_sha256 != "" &&
    var.wazuh_release_attestation_sha256 != "" &&
    var.wazuh_rolesanywhere_ca_path != "" &&
    var.wazuh_rolesanywhere_issuer_cn != "" &&
    var.service_role_permissions_boundary_arn != "" &&
    var.price_report_sha256 != "" &&
    var.approved_vm_monthly_estimate_usd > 0 &&
    var.approved_vm_monthly_estimate_usd < var.vm_monthly_budget_usd
  )
  lightsail_compute_enabled = (
    local.compute_enabled && var.compute_strategy == "accept_transient_lightsail_defaults"
  )
  ec2_compute_enabled = (
    local.compute_enabled && var.compute_strategy == "ec2_zero_ingress"
  )

  nodes = {
    watch = {
      platform             = "lightsail-debian-existing"
      architecture         = "amd64"
      monthly_estimate_usd = 40.00
      managed_by_this_root = false
    }
    core = {
      platform             = "lightsail-ubuntu-24.04"
      architecture         = "amd64"
      monthly_estimate_usd = 10.00
      managed_by_this_root = true
    }
    mdm = {
      platform             = "lightsail-ubuntu-24.04"
      architecture         = "amd64"
      monthly_estimate_usd = 10.00
      managed_by_this_root = true
    }
    siem = {
      platform             = "lightsail-ubuntu-24.04-compute-optimized"
      architecture         = "amd64"
      monthly_estimate_usd = 80.00
      managed_by_this_root = true
    }
    edge = {
      platform             = "lightsail-ubuntu-24.04-ipv6-only"
      architecture         = "amd64"
      monthly_estimate_usd = 3.50
      managed_by_this_root = true
    }
    relay = {
      platform             = "ec2-t4g.nano-ubuntu-24.04"
      architecture         = "arm64"
      monthly_estimate_usd = 4.27
      managed_by_this_root = true
    }
  }

  steady_state_vm_estimate_usd = sum([for node in values(local.nodes) : node.monthly_estimate_usd])
}

resource "terraform_data" "mutation_gate" {
  count = var.cloud_mutations_authorized ? 1 : 0

  input = {
    approval_reference = var.immediate_approval_reference
    broker_enabled     = var.broker_stack_enabled
    compute_enabled    = var.compute_stack_enabled
    compute_strategy   = var.compute_strategy
    protected_watch    = var.protected_watch_arn
    wazuh_integrity    = var.wazuh_integrity_stack_enabled
  }

  lifecycle {
    precondition {
      condition     = var.immediate_approval_reference != ""
      error_message = "Cloud mutations require a fresh immediate_approval_reference."
    }
    precondition {
      condition     = var.compute_strategy != "unselected"
      error_message = "Compute is blocked until the Lightsail transient-ingress versus EC2 choice is explicit."
    }
    precondition {
      condition     = local.steady_state_vm_estimate_usd <= var.vm_monthly_budget_usd
      error_message = "The declared steady-state VM estimate exceeds the approved USD 150 gate."
    }
    precondition {
      condition = !var.broker_stack_enabled || alltrue([
        var.broker_domain_name != "",
        var.broker_certificate_arn != "",
        var.broker_truststore_uri != "",
        var.broker_truststore_version != "",
        var.scanner_client_cert_sha256 != "",
        var.core_scan_verify_key != "",
        var.scanner_result_verify_key != "",
        var.cloudflare_account_id != "",
        var.r2_bucket_name != "",
        var.core_rolesanywhere_ca_path != "",
        var.core_rolesanywhere_issuer_cn != "",
        var.core_rolesanywhere_subject_cn != "",
        var.service_role_permissions_boundary_arn != "",
      ])
      error_message = "The broker stack requires all public identity, mTLS, R2, and verification-key bindings."
    }
    precondition {
      condition = !var.broker_stack_enabled || (
        startswith(var.broker_certificate_arn, "arn:aws:acm:${var.region}:${var.aws_account_id}:certificate/") &&
        can(regex("^s3://plntir-[a-z0-9-]+-${var.aws_account_id}/", var.broker_truststore_uri))
      )
      error_message = "The ACM certificate and truststore must be bound to the selected AWS account."
    }
    precondition {
      condition = !var.broker_stack_enabled || alltrue([
        fileexists(var.kms_broker_artifact_path),
        fileexists(var.scan_result_broker_artifact_path),
        fileexists(var.core_rolesanywhere_ca_path),
      ])
      error_message = "Build both deterministic Lambda ZIPs and provide the public Roles Anywhere CA before enabling the broker stack."
    }
    precondition {
      condition = !var.broker_stack_enabled || (
        fileexists(var.core_rolesanywhere_ca_path) ? (
          can(regex(
            "-----BEGIN CERTIFICATE-----[\\s\\S]+-----END CERTIFICATE-----",
            file(var.core_rolesanywhere_ca_path),
          )) &&
          !can(regex("PRIVATE KEY", file(var.core_rolesanywhere_ca_path)))
        ) : false
      )
      error_message = "core_rolesanywhere_ca_path must contain a public PEM certificate. Private keys must remain outside Terraform."
    }
    precondition {
      condition = !var.wazuh_integrity_stack_enabled || alltrue([
        var.wazuh_last_stage_approved,
        var.wazuh_siem_qualification_sha256 != "",
        var.wazuh_offline_bundle_sha256 != "",
        var.wazuh_release_attestation_sha256 != "",
        var.wazuh_rolesanywhere_ca_path != "",
        var.wazuh_rolesanywhere_issuer_cn != "",
        var.service_role_permissions_boundary_arn != "",
        var.price_report_sha256 != "",
        var.approved_vm_monthly_estimate_usd > 0,
        var.approved_vm_monthly_estimate_usd < var.vm_monthly_budget_usd,
      ])
      error_message = "The Wazuh integrity plane is last-stage only and requires signed release/isolation proofs plus a refreshed VM estimate strictly below USD 150."
    }
    precondition {
      condition = !var.wazuh_integrity_stack_enabled || (
        fileexists(var.wazuh_rolesanywhere_ca_path) &&
        can(regex(
          "-----BEGIN CERTIFICATE-----[\\s\\S]+-----END CERTIFICATE-----",
          file(var.wazuh_rolesanywhere_ca_path),
        )) &&
        !can(regex("PRIVATE KEY", file(var.wazuh_rolesanywhere_ca_path)))
      )
      error_message = "wazuh_rolesanywhere_ca_path must be an existing public PEM certificate and must never contain a private key."
    }
  }
}
