output "planning_gate" {
  description = "Non-secret review status; this does not authorize apply."
  value = {
    cloud_mutations_authorized = var.cloud_mutations_authorized
    broker_stack_enabled       = var.broker_stack_enabled
    compute_stack_enabled      = var.compute_stack_enabled
    wazuh_integrity_enabled    = var.wazuh_integrity_stack_enabled
    wazuh_alerts_qualified     = var.wazuh_alert_routes_qualified
    compute_strategy           = var.compute_strategy
    ec2_architecture_approved  = var.ec2_zero_ingress_architecture_approved
    ec2_transport_proof        = var.ec2_outbound_transport_proof_sha256
    region                     = var.region
    account_id                 = var.aws_account_id
    protected_watch_managed    = false
  }
}

output "wazuh_integrity_runtime" {
  description = "Non-secret SIEM integrity references. Alerting is operational only after the separate email/SMS delivery seal is true."
  value = local.wazuh_integrity_enabled ? {
    bucket_arn                 = aws_s3_bucket.wazuh_integrity[0].arn
    kms_key_arn                = aws_kms_key.wazuh_integrity[0].arn
    alert_topic_arn            = aws_sns_topic.wazuh_alerts[0].arn
    rolesanywhere_profile_arn  = aws_rolesanywhere_profile.wazuh[0].arn
    rolesanywhere_anchor_arn   = aws_rolesanywhere_trust_anchor.wazuh[0].arn
    role_arn                   = aws_iam_role.wazuh_integrity[0].arn
    compliance_retention_days  = 90
    alert_routes_qualified     = var.wazuh_alert_routes_qualified
    release_version            = var.wazuh_release_version
    release_attestation_sha256 = var.wazuh_release_attestation_sha256
    siem_qualification_sha256  = var.wazuh_siem_qualification_sha256
  } : null
}

output "compute_runtime" {
  description = "Non-secret node references; null until an approved compute strategy is enabled."
  value = local.compute_enabled ? {
    strategy = var.compute_strategy
    lightsail_nodes = {
      for role, instance in aws_lightsail_instance.node : role => {
        arn         = instance.arn
        private_ip  = instance.private_ip_address
        ipv6        = instance.ipv6_addresses
        public_ipv4 = instance.public_ip_address
      }
    }
    ec2_nodes = merge(
      {
        for role, instance in aws_instance.zero_ingress : role => {
          arn         = instance.arn
          id          = instance.id
          private_ip  = instance.private_ip
          ipv6        = instance.ipv6_addresses
          public_ipv4 = instance.public_ip
        }
      },
      local.lightsail_compute_enabled ? {
        relay = {
          arn         = aws_instance.lightsail_relay[0].arn
          id          = aws_instance.lightsail_relay[0].id
          private_ip  = aws_instance.lightsail_relay[0].private_ip
          ipv6        = aws_instance.lightsail_relay[0].ipv6_addresses
          public_ipv4 = aws_instance.lightsail_relay[0].public_ip
        }
      } : {},
    )
    monthly_estimate_usd       = var.approved_vm_monthly_estimate_usd
    price_checked_at           = var.price_checked_at
    price_report_sha256        = var.price_report_sha256
    ec2_transport_proof_sha256 = var.compute_strategy == "ec2_zero_ingress" ? var.ec2_outbound_transport_proof_sha256 : null
  } : null
}

output "scan_broker_runtime" {
  description = "Non-secret runtime references. Null until the separately approved broker stack is enabled."
  value = local.broker_enabled ? {
    api_id                    = aws_apigatewayv2_api.scan_brokers[0].id
    api_execution_arn         = aws_apigatewayv2_api.scan_brokers[0].execution_arn
    custom_domain             = aws_apigatewayv2_domain_name.scan_brokers[0].domain_name
    custom_domain_target      = aws_apigatewayv2_domain_name.scan_brokers[0].domain_name_configuration[0].target_domain_name
    file_dek_key_arn          = aws_kms_key.file_deks[0].arn
    scan_result_queue_arn     = aws_sqs_queue.scan_results[0].arn
    scan_result_queue_url     = aws_sqs_queue.scan_results[0].url
    core_role_arn             = aws_iam_role.core_scan_result_consumer[0].arn
    rolesanywhere_profile_arn = aws_rolesanywhere_profile.core[0].arn
    rolesanywhere_anchor_arn  = aws_rolesanywhere_trust_anchor.core[0].arn
  } : null
}

output "node_cost_model" {
  description = "Static pre-creation estimate; prices must be refreshed immediately before a change set."
  value = {
    nodes                         = local.nodes
    steady_state_vm_estimate_usd  = local.steady_state_vm_estimate_usd
    selected_vm_estimate_usd      = var.approved_vm_monthly_estimate_usd
    steady_state_vm_budget_usd    = var.vm_monthly_budget_usd
    ancillary_aws_budget_usd      = var.aws_service_monthly_budget_usd
    temporary_migration_limit_usd = 50
  }
}
