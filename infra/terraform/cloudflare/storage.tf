resource "cloudflare_r2_bucket" "files" {
  count = local.storage_enabled ? 1 : 0

  account_id    = var.cloudflare_account_id
  name          = var.r2_bucket_name
  storage_class = "Standard"

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_r2_bucket_lock" "files" {
  count = local.storage_enabled ? 1 : 0

  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.files[0].name
  rules = [{
    id      = "plntir-files-30-day-retention"
    enabled = true
    prefix  = ""
    condition = {
      type            = "Age"
      max_age_seconds = var.r2_lock_days * 24 * 60 * 60
    }
  }]

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_queue" "scan_dead_letter" {
  count = local.storage_enabled ? 1 : 0

  account_id = var.cloudflare_account_id
  queue_name = var.scanner_dead_letter_queue_name
  settings = {
    delivery_delay           = 0
    delivery_paused          = false
    message_retention_period = 1209600
  }
}

resource "cloudflare_queue" "scan_events" {
  count = local.storage_enabled ? 1 : 0

  account_id = var.cloudflare_account_id
  queue_name = var.scanner_queue_name
  settings = {
    delivery_delay           = 0
    delivery_paused          = false
    message_retention_period = 1209600
  }
}

resource "cloudflare_r2_bucket_event_notification" "scan_objects" {
  count = local.scanner_event_enabled ? 1 : 0

  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.files[0].name
  queue_id    = cloudflare_queue.scan_events[0].queue_id
  rules = [{
    actions     = ["PutObject", "CompleteMultipartUpload"]
    description = "Qualified Plntir scanner release ${var.scanner_release_sha256}"
    prefix      = "objects/"
  }]

  depends_on = [cloudflare_r2_bucket_lock.files]
}

resource "cloudflare_r2_bucket" "wazuh_anchors" {
  count = local.wazuh_anchor_storage_enabled ? 1 : 0

  account_id    = var.cloudflare_account_id
  name          = var.wazuh_anchor_bucket_name
  storage_class = "Standard"

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_r2_bucket_lock" "wazuh_anchors" {
  count = local.wazuh_anchor_storage_enabled ? 1 : 0

  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.wazuh_anchors[0].name
  rules = [{
    id      = "plntir-wazuh-anchors-180-day-retention"
    enabled = true
    prefix  = "anchors/"
    condition = {
      type            = "Age"
      max_age_seconds = var.wazuh_anchor_lock_days * 24 * 60 * 60
    }
  }]

  lifecycle {
    prevent_destroy = true
  }
}
