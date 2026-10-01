mock_provider "cloudflare" {}

run "wazuh_anchor_storage_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(cloudflare_r2_bucket.wazuh_anchors) == 0 &&
      length(cloudflare_r2_bucket_lock.wazuh_anchors) == 0 &&
      output.wazuh_anchor_storage == null
    )
    error_message = "The default plan must not create external Wazuh anchor storage."
  }
}

run "wazuh_anchor_storage_is_separate_and_locked" {
  command = plan

  variables {
    cloudflare_account_id              = "11111111111111111111111111111111"
    cloudflare_zone_id                 = "22222222222222222222222222222222"
    cloud_mutations_authorized         = true
    immediate_approval_reference       = "approved-20260904T140000Z"
    wazuh_anchor_storage_enabled       = true
    wazuh_anchor_worker_release_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  assert {
    condition = (
      length(cloudflare_r2_bucket.wazuh_anchors) == 1 &&
      length(cloudflare_r2_bucket_lock.wazuh_anchors) == 1 &&
      length(cloudflare_r2_bucket.files) == 0 &&
      cloudflare_r2_bucket.wazuh_anchors[0].name != var.r2_bucket_name
    )
    error_message = "Wazuh anchors require one separate bucket and no implicit Fileshare storage."
  }

  assert {
    condition = (
      cloudflare_r2_bucket_lock.wazuh_anchors[0].rules[0].prefix == "anchors/" &&
      cloudflare_r2_bucket_lock.wazuh_anchors[0].rules[0].condition.max_age_seconds == 15552000 &&
      output.wazuh_anchor_storage.edge_qualified == false
    )
    error_message = "Anchors must be locked for 180 days and must not claim an untested Worker edge."
  }
}

run "wazuh_anchor_storage_rejects_unsigned_worker" {
  command = plan

  variables {
    cloudflare_account_id        = "11111111111111111111111111111111"
    cloudflare_zone_id           = "22222222222222222222222222222222"
    cloud_mutations_authorized   = true
    immediate_approval_reference = "approved-20260904T141500Z"
    wazuh_anchor_storage_enabled = true
  }

  expect_failures = [terraform_data.mutation_gate]
}
