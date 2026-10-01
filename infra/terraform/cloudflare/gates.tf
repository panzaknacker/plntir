locals {
  access_enabled        = var.cloud_mutations_authorized && var.access_stack_enabled
  storage_enabled       = var.cloud_mutations_authorized && var.storage_stack_enabled
  scanner_event_enabled = local.storage_enabled && var.scanner_event_binding_enabled
  wazuh_anchor_storage_enabled = (
    var.cloud_mutations_authorized && var.wazuh_anchor_storage_enabled
  )
}

resource "terraform_data" "mutation_gate" {
  count = var.cloud_mutations_authorized ? 1 : 0

  input = {
    approval_reference = var.immediate_approval_reference
    access_enabled     = var.access_stack_enabled
    account_id         = var.cloudflare_account_id
    scanner_event      = var.scanner_event_binding_enabled
    storage_enabled    = var.storage_stack_enabled
    wazuh_anchor       = var.wazuh_anchor_storage_enabled
    zone_id            = var.cloudflare_zone_id
  }

  lifecycle {
    precondition {
      condition     = var.immediate_approval_reference != ""
      error_message = "Cloudflare mutations require a fresh immediate_approval_reference."
    }
    precondition {
      condition     = var.cloudflare_account_id != "00000000000000000000000000000000"
      error_message = "Replace the account-id sentinel before enabling mutations."
    }
    precondition {
      condition     = var.cloudflare_zone_id != "00000000000000000000000000000000"
      error_message = "Replace the zone-id sentinel before enabling mutations."
    }
    precondition {
      condition     = !var.scanner_event_binding_enabled || var.storage_stack_enabled
      error_message = "The scanner event binding requires the managed R2 and Queue storage stack."
    }
    precondition {
      condition     = !var.scanner_event_binding_enabled || var.scanner_release_sha256 != ""
      error_message = "The R2 event rule remains blocked until a qualified scanner release SHA-256 is recorded."
    }
    precondition {
      condition     = !var.wazuh_anchor_storage_enabled || var.wazuh_anchor_worker_release_sha256 != ""
      error_message = "The separate Wazuh anchor bucket requires a signed, qualified Worker release digest."
    }
    precondition {
      condition     = !var.access_stack_enabled || var.admin_email != ""
      error_message = "The Access stack requires the canonical master-admin email."
    }
    precondition {
      condition     = !var.access_stack_enabled || var.warp_enrollment_policy_verified
      error_message = "Access remains blocked until WARP enrollment restrictions and bootstrap-token revocation are verified."
    }
    precondition {
      condition     = !var.access_stack_enabled || var.independent_mfa_entitlement_verified
      error_message = "Access remains blocked until the independent hardware-key MFA entitlement is verified."
    }
  }
}
