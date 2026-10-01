mock_provider "aws" {}

run "wazuh_integrity_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(aws_s3_bucket.wazuh_integrity) == 0 &&
      length(aws_kms_key.wazuh_integrity) == 0 &&
      length(aws_sns_topic.wazuh_alerts) == 0 &&
      length(aws_rolesanywhere_profile.wazuh) == 0
    )
    error_message = "The default plan must contain no Wazuh integrity resources."
  }

  assert {
    condition     = output.wazuh_integrity_runtime == null
    error_message = "Disabled Wazuh runtime output must be null."
  }
}

run "wazuh_integrity_is_append_only_and_bounded" {
  command = plan

  variables {
    cloud_mutations_authorized            = true
    immediate_approval_reference          = "approved-20260904T130000Z"
    compute_strategy                      = "ec2_zero_ingress"
    wazuh_integrity_stack_enabled         = true
    wazuh_last_stage_approved             = true
    wazuh_siem_qualification_sha256       = "1111111111111111111111111111111111111111111111111111111111111111"
    wazuh_offline_bundle_sha256           = "2222222222222222222222222222222222222222222222222222222222222222"
    wazuh_release_attestation_sha256      = "3333333333333333333333333333333333333333333333333333333333333333"
    wazuh_rolesanywhere_ca_path           = "tests/fixtures/mock-public-ca.crt"
    wazuh_rolesanywhere_issuer_cn         = "Plntir Terraform Mock CA"
    service_role_permissions_boundary_arn = "arn:aws:iam::444455556666:policy/plntir/boundary/PlntirServiceBoundary"
    price_report_sha256                   = "4444444444444444444444444444444444444444444444444444444444444444"
    approved_vm_monthly_estimate_usd      = 147.77
  }

  assert {
    condition = (
      length(aws_s3_bucket.wazuh_integrity) == 1 &&
      length(aws_s3_bucket_object_lock_configuration.wazuh_integrity) == 1 &&
      length(aws_kms_key.wazuh_integrity) == 1 &&
      length(aws_sns_topic.wazuh_alerts) == 1 &&
      length(aws_rolesanywhere_profile.wazuh) == 1
    )
    error_message = "The approved Wazuh integrity plan is missing a required isolated resource."
  }

  assert {
    condition = (
      aws_s3_bucket.wazuh_integrity[0].object_lock_enabled &&
      aws_s3_bucket.wazuh_integrity[0].force_destroy == false &&
      aws_s3_bucket_object_lock_configuration.wazuh_integrity[0].rule[0].default_retention[0].mode == "COMPLIANCE" &&
      aws_s3_bucket_object_lock_configuration.wazuh_integrity[0].rule[0].default_retention[0].days == 90 &&
      aws_s3_bucket_versioning.wazuh_integrity[0].versioning_configuration[0].status == "Enabled"
    )
    error_message = "Wazuh evidence must use versioning and exactly 90-day Object Lock Compliance retention."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.wazuh_integrity[0].block_public_acls &&
      aws_s3_bucket_public_access_block.wazuh_integrity[0].block_public_policy &&
      aws_s3_bucket_public_access_block.wazuh_integrity[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.wazuh_integrity[0].restrict_public_buckets
    )
    error_message = "Every public S3 access path must remain blocked."
  }

  assert {
    condition = (
      aws_iam_role.wazuh_integrity[0].max_session_duration == 3600 &&
      aws_iam_role.wazuh_integrity[0].permissions_boundary == var.service_role_permissions_boundary_arn &&
      aws_rolesanywhere_profile.wazuh[0].duration_seconds == 3600 &&
      length(aws_rolesanywhere_profile.wazuh[0].role_arns) == 1
    )
    error_message = "The isolated SIEM identity must be bounded and expire after one hour."
  }

  assert {
    condition     = output.wazuh_integrity_runtime.alert_routes_qualified == false
    error_message = "A planned SNS topic must not claim email/SMS delivery before the out-of-band seal."
  }
}

run "wazuh_integrity_rejects_missing_last_stage_proofs" {
  command = plan

  variables {
    cloud_mutations_authorized    = true
    immediate_approval_reference  = "approved-20260904T131500Z"
    compute_strategy              = "ec2_zero_ingress"
    wazuh_integrity_stack_enabled = true
  }

  expect_failures = [terraform_data.mutation_gate]
}
