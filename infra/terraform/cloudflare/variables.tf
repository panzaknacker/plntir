variable "cloudflare_account_id" {
  description = "Cloudflare account id, supplied in a gitignored tfvars file."
  type        = string
  default     = "00000000000000000000000000000000"

  validation {
    condition     = can(regex("^[a-f0-9]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be 32 lowercase hexadecimal characters."
  }
}

variable "cloudflare_zone_id" {
  description = "Zone id for plntir.example, supplied in a gitignored tfvars file."
  type        = string
  default     = "00000000000000000000000000000000"

  validation {
    condition     = can(regex("^[a-f0-9]{32}$", var.cloudflare_zone_id))
    error_message = "cloudflare_zone_id must be 32 lowercase hexadecimal characters."
  }
}

variable "cloud_mutations_authorized" {
  description = "Fail-safe switch. Keep false for init, validate, and read-only plans."
  type        = bool
  default     = false
}

variable "immediate_approval_reference" {
  description = "Non-secret UTC marker recorded only after immediate human approval of a mutation window."
  type        = string
  default     = ""

  validation {
    condition     = var.immediate_approval_reference == "" || can(regex("^approved-[0-9]{8}T[0-9]{6}Z$", var.immediate_approval_reference))
    error_message = "Use approved-YYYYMMDDTHHMMSSZ or leave the value empty."
  }
}

variable "cloudflare_monthly_budget_usd" {
  description = "R2, Workers, Queues and scanner container ceiling."
  type        = number
  default     = 50

  validation {
    condition     = var.cloudflare_monthly_budget_usd > 0 && var.cloudflare_monthly_budget_usd <= 50
    error_message = "The v1 Cloudflare platform budget may not exceed USD 50."
  }
}

variable "storage_stack_enabled" {
  description = "Creates only the R2 bucket, 30-day lock, and scanner queues during an approved mutation window."
  type        = bool
  default     = false
}

variable "access_stack_enabled" {
  description = "Creates only the OTP IdP, WARP/Gateway posture checks, and the two self-hosted Access applications during an approved mutation window."
  type        = bool
  default     = false
}

variable "admin_email" {
  description = "Canonical lower-case email identity permitted to reach admin.plntir.example through the OTP IdP."
  type        = string
  default     = ""

  validation {
    condition = var.admin_email == "" || (
      var.admin_email == lower(trimspace(var.admin_email)) &&
      can(regex("^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.admin_email))
    )
    error_message = "admin_email must be one canonical lower-case email address, or empty while Access is disabled."
  }
}

variable "warp_enrollment_policy_verified" {
  description = "Explicit seal-time assertion that only approved device enrollment methods remain enabled and bootstrap service tokens have been revoked."
  type        = bool
  default     = false
}

variable "independent_mfa_entitlement_verified" {
  description = "Explicit seal-time assertion that the account entitlement supports Access independent MFA with hardware security keys."
  type        = bool
  default     = false
}

variable "scanner_event_binding_enabled" {
  description = "Separately enables the R2-to-Queue event rule after the scanner Worker release is qualified and deployed."
  type        = bool
  default     = false
}

variable "scanner_release_sha256" {
  description = "Non-secret SHA-256 of the independently built and qualified scanner release bound to the event-rule approval."
  type        = string
  default     = ""

  validation {
    condition     = var.scanner_release_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.scanner_release_sha256))
    error_message = "scanner_release_sha256 must be 64 lower-case hexadecimal characters, or empty while the event rule is disabled."
  }
}

variable "r2_bucket_name" {
  description = "Opaque ciphertext bucket used by Fileshare."
  type        = string
  default     = "plntir-files"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.r2_bucket_name))
    error_message = "r2_bucket_name must be a 3-63 character lower-case bucket name."
  }
}

variable "scanner_queue_name" {
  description = "Queue receiving object-create notifications for the scanner."
  type        = string
  default     = "plntir-scan-events"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.scanner_queue_name))
    error_message = "scanner_queue_name must be a bounded lower-case queue name."
  }
}

variable "scanner_dead_letter_queue_name" {
  description = "Queue retaining scanner events that exhaust Worker retries."
  type        = string
  default     = "plntir-scan-dead-letter"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.scanner_dead_letter_queue_name))
    error_message = "scanner_dead_letter_queue_name must be a bounded lower-case queue name."
  }
}

variable "r2_lock_days" {
  description = "V1 invariant: immutable ciphertext objects remain locked for exactly 30 days."
  type        = number
  default     = 30

  validation {
    condition     = var.r2_lock_days == 30
    error_message = "Plntir v1 requires an exact 30-day R2 bucket lock."
  }
}

variable "wazuh_anchor_storage_enabled" {
  description = "Creates only the separate locked R2 bucket for daily Wazuh hash anchors during an approved mutation window."
  type        = bool
  default     = false
}

variable "wazuh_anchor_bucket_name" {
  description = "Separate R2 bucket for signed daily Wazuh hash-chain anchors; never shared with Fileshare bytes."
  type        = string
  default     = "plntir-wazuh-hash-anchors"

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.wazuh_anchor_bucket_name)) &&
      var.wazuh_anchor_bucket_name != var.r2_bucket_name
    )
    error_message = "The Wazuh anchor bucket must be a distinct bounded lower-case R2 bucket name."
  }
}

variable "wazuh_anchor_lock_days" {
  description = "V1 invariant: signed daily SIEM anchors remain locked for the 180-day security-metadata window."
  type        = number
  default     = 180

  validation {
    condition     = var.wazuh_anchor_lock_days == 180
    error_message = "Plntir v1 requires exactly 180 days of R2 lock for Wazuh hash anchors."
  }
}

variable "wazuh_anchor_worker_release_sha256" {
  description = "SHA-256 of the signed and qualified mTLS Wazuh anchor Worker release."
  type        = string
  default     = ""

  validation {
    condition     = var.wazuh_anchor_worker_release_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.wazuh_anchor_worker_release_sha256))
    error_message = "wazuh_anchor_worker_release_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "wazuh_anchor_edge_qualified" {
  description = "Seal marker set only after the Worker route, mTLS CA/leaf pin, immutable retry, and daily restore checks pass."
  type        = bool
  default     = false
}
