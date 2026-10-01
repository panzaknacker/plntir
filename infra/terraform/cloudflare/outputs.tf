output "planning_gate" {
  description = "Non-secret review status; this does not authorize apply."
  value = {
    cloud_mutations_authorized  = var.cloud_mutations_authorized
    access_stack_enabled        = var.access_stack_enabled
    storage_stack_enabled       = var.storage_stack_enabled
    scanner_event_enabled       = var.scanner_event_binding_enabled
    wazuh_anchor_storage        = var.wazuh_anchor_storage_enabled
    wazuh_anchor_edge_qualified = var.wazuh_anchor_edge_qualified
    account_configured          = var.cloudflare_account_id != "00000000000000000000000000000000"
    zone_configured             = var.cloudflare_zone_id != "00000000000000000000000000000000"
    monthly_budget_usd          = var.cloudflare_monthly_budget_usd
    tunnel_credentials_in_state = false
  }
}

output "wazuh_anchor_storage" {
  description = "Non-secret external anchor storage status; it is operational only after the separate Worker/mTLS qualification seal."
  value = local.wazuh_anchor_storage_enabled ? {
    bucket_name           = cloudflare_r2_bucket.wazuh_anchors[0].name
    bucket_lock_days      = var.wazuh_anchor_lock_days
    worker_release_sha256 = var.wazuh_anchor_worker_release_sha256
    edge_qualified        = var.wazuh_anchor_edge_qualified
  } : null
}

output "access_topology" {
  description = "Non-secret Access references; null until the separately approved Access stack is enabled."
  value = local.access_enabled ? {
    admin_application_id     = cloudflare_zero_trust_access_application.admin[0].id
    fileshare_application_id = cloudflare_zero_trust_access_application.fileshare[0].id
    otp_identity_provider_id = cloudflare_zero_trust_access_identity_provider.otp[0].id
    warp_posture_rule_id     = cloudflare_zero_trust_device_posture_rule.warp[0].id
    gateway_posture_rule_id  = cloudflare_zero_trust_device_posture_rule.gateway[0].id
  } : null
}

output "scanner_storage" {
  description = "Non-secret R2 and Queue references; null until the separately approved storage stack is enabled."
  value = local.storage_enabled ? {
    bucket_name            = cloudflare_r2_bucket.files[0].name
    bucket_lock_days       = var.r2_lock_days
    event_binding_enabled  = local.scanner_event_enabled
    scanner_queue_id       = cloudflare_queue.scan_events[0].queue_id
    scanner_queue_name     = cloudflare_queue.scan_events[0].queue_name
    dead_letter_queue_id   = cloudflare_queue.scan_dead_letter[0].queue_id
    dead_letter_queue_name = cloudflare_queue.scan_dead_letter[0].queue_name
    scanner_release_sha256 = var.scanner_event_binding_enabled ? var.scanner_release_sha256 : null
  } : null
}
