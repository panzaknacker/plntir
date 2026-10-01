locals {
  wazuh_integrity_bucket_name = "plntir-wazuh-integrity-${var.aws_account_id}"
}

resource "terraform_data" "wazuh_integrity_gate" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  input = {
    approval_reference  = var.immediate_approval_reference
    release_version     = var.wazuh_release_version
    release_attestation = var.wazuh_release_attestation_sha256
    offline_bundle      = var.wazuh_offline_bundle_sha256
    siem_qualification  = var.wazuh_siem_qualification_sha256
    monthly_estimate    = var.approved_vm_monthly_estimate_usd
  }

  lifecycle {
    precondition {
      condition     = var.wazuh_release_version == "4.14.7"
      error_message = "Wazuh v1 is pinned to the reviewed 4.14.7 offline release."
    }
    precondition {
      condition = (
        var.wazuh_last_stage_approved &&
        var.approved_vm_monthly_estimate_usd > 0 &&
        var.approved_vm_monthly_estimate_usd < var.vm_monthly_budget_usd
      )
      error_message = "Wazuh may be created only as the approved last VM stage while the refreshed total remains strictly below USD 150."
    }
  }
}

resource "aws_kms_key" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  description                        = "Plntir Wazuh Object-Lock records and independent SNS alerts"
  deletion_window_in_days            = 30
  enable_key_rotation                = true
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  bypass_policy_lockout_safety_check = false

  tags = {
    Name    = "plntir-wazuh-integrity"
    Purpose = "isolated-siem-integrity-and-alerts"
  }

  depends_on = [terraform_data.wazuh_integrity_gate]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name          = "alias/plntir-wazuh-integrity"
  target_key_id = aws_kms_key.wazuh_integrity[0].key_id
}

resource "aws_s3_bucket" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket              = local.wazuh_integrity_bucket_name
  force_destroy       = false
  object_lock_enabled = true

  tags = {
    Name      = local.wazuh_integrity_bucket_name
    Purpose   = "wazuh-append-only-integrity"
    Retention = "90-day-compliance"
  }

  depends_on = [terraform_data.wazuh_integrity_gate]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket = aws_s3_bucket.wazuh_integrity[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket = aws_s3_bucket.wazuh_integrity[0].id
  rule {
    bucket_key_enabled = false
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.wazuh_integrity[0].arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket = aws_s3_bucket.wazuh_integrity[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.wazuh_integrity[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket              = aws_s3_bucket.wazuh_integrity[0].id
  object_lock_enabled = "Enabled"

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.wazuh_integrity]
}

resource "aws_s3_bucket_lifecycle_configuration" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket = aws_s3_bucket.wazuh_integrity[0].id

  rule {
    id     = "expire-after-compliance-window"
    status = "Enabled"

    filter {}

    expiration {
      days = 91
    }

    noncurrent_version_expiration {
      noncurrent_days = 91
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_object_lock_configuration.wazuh_integrity]
}

resource "aws_sns_topic" "wazuh_alerts" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name              = "plntir-wazuh-independent-alerts"
  display_name      = "Plntir Wazuh"
  kms_master_key_id = aws_kms_key.wazuh_integrity[0].arn

  tags = {
    Purpose = "core-and-cloudflare-independent-siem-alerts"
  }

  depends_on = [terraform_data.wazuh_integrity_gate]
}

resource "aws_rolesanywhere_trust_anchor" "wazuh" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name    = "plntir-wazuh-runtime"
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"
    source_data {
      x509_certificate_data = local.wazuh_integrity_enabled ? file(var.wazuh_rolesanywhere_ca_path) : ""
    }
  }

  tags = {
    Purpose = "siem-short-lived-append-and-alert-credentials"
  }
}

resource "aws_iam_role" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name                 = "plntir-wazuh-integrity"
  path                 = "/plntir/service/"
  description          = "Short-lived Roles Anywhere identity for append-only SIEM records and SNS alerts"
  max_session_duration = 3600
  permissions_boundary = var.service_role_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "OnlyBoundWazuhCertificate"
      Effect = "Allow"
      Principal = {
        Service = "rolesanywhere.amazonaws.com"
      }
      Action = [
        "sts:AssumeRole",
        "sts:SetSourceIdentity",
        "sts:TagSession",
      ]
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_rolesanywhere_trust_anchor.wazuh[0].arn
        }
        StringEquals = {
          "aws:SourceAccount"               = var.aws_account_id
          "aws:PrincipalTag/x509Issuer/CN"  = var.wazuh_rolesanywhere_issuer_cn
          "aws:PrincipalTag/x509Subject/CN" = var.wazuh_rolesanywhere_subject_cn
          "sts:SourceIdentity"              = var.wazuh_rolesanywhere_subject_cn
        }
      }
    }]
  })

  tags = {
    Purpose = "wazuh-append-only-integrity-and-alerts"
  }
}

resource "aws_iam_role_policy" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name = "plntir-wazuh-integrity"
  role = aws_iam_role.wazuh_integrity[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InspectOwnMultipartUploads"
        Effect   = "Allow"
        Action   = "s3:ListBucketMultipartUploads"
        Resource = aws_s3_bucket.wazuh_integrity[0].arn
      },
      {
        Sid    = "AppendOnlyIntegrityObjects"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
      },
      {
        Sid    = "EncryptIntegrityObjectsOnlyThroughS3"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = aws_kms_key.wazuh_integrity[0].arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com"
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
          }
        }
      },
      {
        Sid      = "PublishOnlyIndependentWazuhAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.wazuh_alerts[0].arn
      },
      {
        Sid    = "EncryptOnlyIndependentAlertsThroughSNS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = aws_kms_key.wazuh_integrity[0].arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                         = "sns.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sns:topicArn" = aws_sns_topic.wazuh_alerts[0].arn
          }
        }
      },
    ]
  })
}

resource "aws_rolesanywhere_profile" "wazuh" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  name                        = "plntir-wazuh-runtime"
  enabled                     = true
  duration_seconds            = 3600
  accept_role_session_name    = false
  require_instance_properties = false
  role_arns                   = [aws_iam_role.wazuh_integrity[0].arn]
  session_policy              = aws_iam_role_policy.wazuh_integrity[0].policy

  tags = {
    Purpose = "siem-short-lived-append-and-alert-credentials"
  }
}

resource "aws_s3_bucket_policy" "wazuh_integrity" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  bucket = aws_s3_bucket.wazuh_integrity[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.wazuh_integrity[0].arn,
          "${aws_s3_bucket.wazuh_integrity[0].arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyMissingKmsEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      },
      {
        Sid       = "DenyWrongEncryptionAlgorithm"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyWrongKmsKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.wazuh_integrity[0].arn
          }
        }
      },
      {
        Sid         = "DenyWritesOutsideImmutableObjectPrefix"
        Effect      = "Deny"
        Principal   = { AWS = aws_iam_role.wazuh_integrity[0].arn }
        Action      = "s3:PutObject"
        NotResource = "${aws_s3_bucket.wazuh_integrity[0].arn}/objects/*"
      },
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.wazuh_integrity,
    aws_s3_bucket_server_side_encryption_configuration.wazuh_integrity,
  ]
}

resource "aws_sns_topic_policy" "wazuh_alerts" {
  count = local.wazuh_integrity_enabled ? 1 : 0

  arn = aws_sns_topic.wazuh_alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OwnerAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action    = "sns:*"
        Resource  = aws_sns_topic.wazuh_alerts[0].arn
      },
      {
        Sid       = "OnlyWazuhRuntimePublishes"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.wazuh_alerts[0].arn
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:*"
        Resource  = aws_sns_topic.wazuh_alerts[0].arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}
