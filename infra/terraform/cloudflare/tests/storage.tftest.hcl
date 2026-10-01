mock_provider "cloudflare" {}

run "storage_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(cloudflare_r2_bucket.files) == 0 &&
      length(cloudflare_queue.scan_events) == 0 &&
      length(cloudflare_r2_bucket_event_notification.scan_objects) == 0
    )
    error_message = "The default Cloudflare plan must not create storage or scanner resources."
  }
}

run "storage_and_qualified_event_topology" {
  command = plan

  variables {
    cloudflare_account_id         = "11111111111111111111111111111111"
    cloudflare_zone_id            = "22222222222222222222222222222222"
    cloud_mutations_authorized    = true
    immediate_approval_reference  = "approved-20260904T130000Z"
    storage_stack_enabled         = true
    scanner_event_binding_enabled = true
    scanner_release_sha256        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  assert {
    condition = (
      length(cloudflare_r2_bucket.files) == 1 &&
      length(cloudflare_r2_bucket_lock.files) == 1 &&
      length(cloudflare_queue.scan_events) == 1 &&
      length(cloudflare_queue.scan_dead_letter) == 1 &&
      length(cloudflare_r2_bucket_event_notification.scan_objects) == 1
    )
    error_message = "The approved scanner storage plan is incomplete."
  }

  assert {
    condition = (
      cloudflare_r2_bucket.files[0].storage_class == "Standard" &&
      cloudflare_r2_bucket_lock.files[0].rules[0].condition.max_age_seconds == 2592000 &&
      cloudflare_r2_bucket_lock.files[0].rules[0].prefix == "" &&
      cloudflare_queue.scan_events[0].settings.message_retention_period == 1209600
    )
    error_message = "R2 lock or Queue retention drifted from v1 invariants."
  }

  assert {
    condition = (
      cloudflare_r2_bucket_event_notification.scan_objects[0].rules[0].prefix == "objects/" &&
      toset(cloudflare_r2_bucket_event_notification.scan_objects[0].rules[0].actions) == toset(["PutObject", "CompleteMultipartUpload"])
    )
    error_message = "Only completed opaque object writes may enter the scanner queue."
  }
}

run "event_binding_requires_qualified_release" {
  command = plan

  variables {
    cloudflare_account_id         = "11111111111111111111111111111111"
    cloudflare_zone_id            = "22222222222222222222222222222222"
    cloud_mutations_authorized    = true
    immediate_approval_reference  = "approved-20260904T130000Z"
    storage_stack_enabled         = true
    scanner_event_binding_enabled = true
  }

  expect_failures = [terraform_data.mutation_gate]
}
