resource "aws_kms_key" "file_deks" {
  count = local.broker_enabled ? 1 : 0

  description                        = "Plntir file DEKs; only the scan broker may unwrap scan-bound ciphertext"
  deletion_window_in_days            = 30
  enable_key_rotation                = true
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  bypass_policy_lockout_safety_check = false

  tags = {
    Name    = "plntir-files"
    Purpose = "file-dek-envelope"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "file_deks" {
  count = local.broker_enabled ? 1 : 0

  name          = "alias/plntir-files"
  target_key_id = aws_kms_key.file_deks[0].key_id
}

resource "aws_kms_key" "scan_results" {
  count = local.broker_enabled ? 1 : 0

  description                        = "Plntir scan-result FIFO queue encryption"
  deletion_window_in_days            = 30
  enable_key_rotation                = true
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  bypass_policy_lockout_safety_check = false

  tags = {
    Name    = "plntir-scan-results"
    Purpose = "sqs-envelope"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "scan_results" {
  count = local.broker_enabled ? 1 : 0

  name          = "alias/plntir-scan-results"
  target_key_id = aws_kms_key.scan_results[0].key_id
}

resource "aws_sqs_queue" "scan_result_dlq" {
  count = local.broker_enabled ? 1 : 0

  name                              = "plntir-scan-results-dlq.fifo"
  fifo_queue                        = true
  content_based_deduplication       = false
  max_message_size                  = 32768
  message_retention_seconds         = 1209600
  receive_wait_time_seconds         = 20
  visibility_timeout_seconds        = 120
  kms_master_key_id                 = aws_kms_key.scan_results[0].arn
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Purpose = "failed-signed-scan-results"
  }
}

resource "aws_sqs_queue" "scan_results" {
  count = local.broker_enabled ? 1 : 0

  name                              = "plntir-scan-results.fifo"
  fifo_queue                        = true
  content_based_deduplication       = false
  max_message_size                  = 32768
  message_retention_seconds         = 345600
  receive_wait_time_seconds         = 20
  visibility_timeout_seconds        = 120
  kms_master_key_id                 = aws_kms_key.scan_results[0].arn
  kms_data_key_reuse_period_seconds = 300
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.scan_result_dlq[0].arn
    maxReceiveCount     = 5
  })

  tags = {
    Purpose = "signed-scan-results"
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "scan_result_dlq" {
  count = local.broker_enabled ? 1 : 0

  queue_url = aws_sqs_queue.scan_result_dlq[0].url
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.scan_results[0].arn]
  })
}

resource "aws_rolesanywhere_trust_anchor" "core" {
  count = local.broker_enabled ? 1 : 0

  name    = "plntir-core-runtime"
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"
    source_data {
      x509_certificate_data = local.broker_enabled ? file(var.core_rolesanywhere_ca_path) : ""
    }
  }

  tags = {
    Purpose = "core-short-lived-sqs-credentials"
  }
}

resource "aws_iam_role" "core_scan_result_consumer" {
  count = local.broker_enabled ? 1 : 0

  name                 = "plntir-core-scan-result-consumer"
  path                 = "/plntir/service/"
  description          = "Short-lived Roles Anywhere identity for the Core scan-result consumer"
  max_session_duration = 3600
  permissions_boundary = var.service_role_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "OnlyBoundCoreCertificate"
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
          "aws:SourceArn" = aws_rolesanywhere_trust_anchor.core[0].arn
        }
        StringEquals = {
          "aws:SourceAccount"               = var.aws_account_id
          "aws:PrincipalTag/x509Issuer/CN"  = var.core_rolesanywhere_issuer_cn
          "aws:PrincipalTag/x509Subject/CN" = var.core_rolesanywhere_subject_cn
          "sts:SourceIdentity"              = var.core_rolesanywhere_subject_cn
        }
      }
    }]
  })

  tags = {
    Purpose = "core-scan-result-consumer"
  }
}

resource "aws_iam_role_policy" "core_scan_result_consumer" {
  count = local.broker_enabled ? 1 : 0

  name = "plntir-core-scan-result-consumer"
  role = aws_iam_role.core_scan_result_consumer[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConsumeOnlyMainScanResultQueue"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.scan_results[0].arn
      },
      {
        Sid      = "DecryptOnlyMainQueueThroughSQS"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.scan_results[0].arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.scan_results[0].arn
          }
        }
      },
    ]
  })
}

resource "aws_rolesanywhere_profile" "core" {
  count = local.broker_enabled ? 1 : 0

  name                        = "plntir-core-runtime"
  enabled                     = true
  duration_seconds            = 3600
  accept_role_session_name    = false
  require_instance_properties = false
  role_arns                   = [aws_iam_role.core_scan_result_consumer[0].arn]
  session_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConsumeOnlyMainScanResultQueue"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.scan_results[0].arn
      },
      {
        Sid      = "DecryptOnlyMainQueueThroughSQS"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.scan_results[0].arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.scan_results[0].arn
          }
        }
      },
    ]
  })

  tags = {
    Purpose = "core-short-lived-sqs-credentials"
  }
}

resource "aws_iam_role" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  name                 = "plntir-kms-broker"
  path                 = "/plntir/service/"
  description          = "Execution role for the scan-only file DEK rewrap broker"
  max_session_duration = 3600
  permissions_boundary = var.service_role_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose = "scan-dek-rewrap"
  }
}

resource "aws_iam_role" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  name                 = "plntir-scan-result-broker"
  path                 = "/plntir/service/"
  description          = "Execution role for the signed scanner-result ingress broker"
  max_session_duration = 3600
  permissions_boundary = var.service_role_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose = "scan-result-ingress"
  }
}

resource "aws_cloudwatch_log_group" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  name              = "/aws/lambda/plntir-kms-broker"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  name              = "/aws/lambda/plntir-scan-result-broker"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "broker_api" {
  count = local.broker_enabled ? 1 : 0

  name              = "/aws/apigateway/plntir-scan-brokers"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  name = "plntir-kms-broker"
  role = aws_iam_role.kms_broker[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecryptOnlySignedFileDEKs"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.file_deks[0].arn
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:plntir-purpose" = "file-dek"
          }
          "ForAllValues:StringEquals" = {
            "kms:EncryptionContextKeys" = [
              "plntir-purpose",
              "plntir-file-version-id",
              "plntir-object-key",
            ]
          }
        }
      },
      {
        Sid    = "WriteOnlyOwnStructuredLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.kms_broker[0].arn}:*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  name = "plntir-scan-result-broker"
  role = aws_iam_role.scan_result_broker[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendOnlySignedScanResults"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.scan_results[0].arn
      },
      {
        Sid    = "EncryptOnlyMainQueueThroughSQS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = aws_kms_key.scan_results[0].arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.scan_results[0].arn
          }
        }
      },
      {
        Sid    = "WriteOnlyOwnStructuredLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.scan_result_broker[0].arn}:*"
      },
    ]
  })
}

resource "aws_sqs_queue_policy" "scan_results" {
  count = local.broker_enabled ? 1 : 0

  queue_url = aws_sqs_queue.scan_results[0].url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.scan_results[0].arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowOnlyResultBrokerToSend"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.scan_result_broker[0].arn
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.scan_results[0].arn
      },
      {
        Sid    = "AllowOnlyCoreToConsume"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.core_scan_result_consumer[0].arn
        }
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.scan_results[0].arn
      },
    ]
  })
}

resource "aws_sqs_queue_policy" "scan_result_dlq" {
  count = local.broker_enabled ? 1 : 0

  queue_url = aws_sqs_queue.scan_result_dlq[0].url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.scan_result_dlq[0].arn
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

resource "aws_apigatewayv2_api" "scan_brokers" {
  count = local.broker_enabled ? 1 : 0

  name                         = "plntir-scan-brokers"
  description                  = "Two-route mTLS ingress for scanner DEK rewrap and signed results"
  protocol_type                = "HTTP"
  ip_address_type              = "dualstack"
  disable_execute_api_endpoint = true
}

resource "aws_lambda_function" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  function_name                  = "plntir-kms-broker"
  description                    = "Rewraps one signed scan-job DEK to one ephemeral container public key"
  role                           = aws_iam_role.kms_broker[0].arn
  filename                       = var.kms_broker_artifact_path
  source_code_hash               = local.broker_enabled ? filebase64sha256(var.kms_broker_artifact_path) : null
  handler                        = "bootstrap"
  runtime                        = "provided.al2023"
  architectures                  = ["arm64"]
  memory_size                    = 256
  timeout                        = 15
  reserved_concurrent_executions = 2
  publish                        = false

  environment {
    variables = {
      PLNTIR_API_DOMAIN                 = var.broker_domain_name
      PLNTIR_API_GATEWAY_ID             = aws_apigatewayv2_api.scan_brokers[0].id
      PLNTIR_CLOUDFLARE_ACCOUNT_ID      = var.cloudflare_account_id
      PLNTIR_CORE_SCAN_VERIFY_KEY       = var.core_scan_verify_key
      PLNTIR_KMS_KEY_ARN                = aws_kms_key.file_deks[0].arn
      PLNTIR_R2_BUCKET                  = var.r2_bucket_name
      PLNTIR_SCANNER_CLIENT_CERT_SHA256 = var.scanner_client_cert_sha256
    }
  }

  ephemeral_storage {
    size = 512
  }

  logging_config {
    application_log_level = "INFO"
    log_format            = "JSON"
    log_group             = aws_cloudwatch_log_group.kms_broker[0].name
    system_log_level      = "WARN"
  }

  depends_on = [aws_iam_role_policy.kms_broker]
}

resource "aws_lambda_function" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  function_name                  = "plntir-scan-result-broker"
  description                    = "Verifies scanner results and enqueues only canonical signed envelopes"
  role                           = aws_iam_role.scan_result_broker[0].arn
  filename                       = var.scan_result_broker_artifact_path
  source_code_hash               = local.broker_enabled ? filebase64sha256(var.scan_result_broker_artifact_path) : null
  handler                        = "bootstrap"
  runtime                        = "provided.al2023"
  architectures                  = ["arm64"]
  memory_size                    = 256
  timeout                        = 10
  reserved_concurrent_executions = 2
  publish                        = false

  environment {
    variables = {
      PLNTIR_API_DOMAIN                 = var.broker_domain_name
      PLNTIR_API_GATEWAY_ID             = aws_apigatewayv2_api.scan_brokers[0].id
      PLNTIR_AWS_ACCOUNT_ID             = var.aws_account_id
      PLNTIR_SCANNER_CLIENT_CERT_SHA256 = var.scanner_client_cert_sha256
      PLNTIR_SCANNER_RESULT_VERIFY_KEY  = var.scanner_result_verify_key
      PLNTIR_SCAN_RESULT_QUEUE_URL      = aws_sqs_queue.scan_results[0].url
    }
  }

  ephemeral_storage {
    size = 512
  }

  logging_config {
    application_log_level = "INFO"
    log_format            = "JSON"
    log_group             = aws_cloudwatch_log_group.scan_result_broker[0].name
    system_log_level      = "WARN"
  }

  depends_on = [aws_iam_role_policy.scan_result_broker]
}

resource "aws_apigatewayv2_integration" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  api_id                 = aws_apigatewayv2_api.scan_brokers[0].id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.kms_broker[0].invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 15000
}

resource "aws_apigatewayv2_integration" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  api_id                 = aws_apigatewayv2_api.scan_brokers[0].id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.scan_result_broker[0].invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 10000
}

resource "aws_apigatewayv2_route" "kms_broker" {
  count = local.broker_enabled ? 1 : 0

  api_id             = aws_apigatewayv2_api.scan_brokers[0].id
  route_key          = "POST /v1/rewrap"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.kms_broker[0].id}"
}

resource "aws_apigatewayv2_route" "scan_result_broker" {
  count = local.broker_enabled ? 1 : 0

  api_id             = aws_apigatewayv2_api.scan_brokers[0].id
  route_key          = "POST /v1/results"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.scan_result_broker[0].id}"
}

resource "aws_apigatewayv2_stage" "scan_brokers" {
  count = local.broker_enabled ? 1 : 0

  api_id      = aws_apigatewayv2_api.scan_brokers[0].id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.broker_api[0].arn
    format = jsonencode({
      domainName       = "$context.domainName"
      errorCode        = "$context.error.responseType"
      httpMethod       = "$context.httpMethod"
      integrationError = "$context.integrationErrorMessage"
      path             = "$context.path"
      requestId        = "$context.requestId"
      requestTimeEpoch = "$context.requestTimeEpoch"
      responseLength   = "$context.responseLength"
      routeKey         = "$context.routeKey"
      sourceIp         = "$context.identity.sourceIp"
      status           = "$context.status"
    })
  }

  default_route_settings {
    detailed_metrics_enabled = true
    throttling_burst_limit   = 10
    throttling_rate_limit    = 5
  }
}

resource "aws_apigatewayv2_domain_name" "scan_brokers" {
  count = local.broker_enabled ? 1 : 0

  domain_name = var.broker_domain_name

  domain_name_configuration {
    certificate_arn = var.broker_certificate_arn
    endpoint_type   = "REGIONAL"
    ip_address_type = "dualstack"
    security_policy = "TLS_1_2"
  }

  mutual_tls_authentication {
    truststore_uri     = var.broker_truststore_uri
    truststore_version = var.broker_truststore_version
  }
}

resource "aws_apigatewayv2_api_mapping" "scan_brokers" {
  count = local.broker_enabled ? 1 : 0

  api_id      = aws_apigatewayv2_api.scan_brokers[0].id
  domain_name = aws_apigatewayv2_domain_name.scan_brokers[0].id
  stage       = aws_apigatewayv2_stage.scan_brokers[0].name
}

resource "aws_lambda_permission" "kms_broker_from_api" {
  count = local.broker_enabled ? 1 : 0

  statement_id   = "AllowExactRewrapRoute"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.kms_broker[0].function_name
  principal      = "apigateway.amazonaws.com"
  source_account = var.aws_account_id
  source_arn     = "${aws_apigatewayv2_api.scan_brokers[0].execution_arn}/*/POST/v1/rewrap"
}

resource "aws_lambda_permission" "scan_result_broker_from_api" {
  count = local.broker_enabled ? 1 : 0

  statement_id   = "AllowExactResultsRoute"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.scan_result_broker[0].function_name
  principal      = "apigateway.amazonaws.com"
  source_account = var.aws_account_id
  source_arn     = "${aws_apigatewayv2_api.scan_brokers[0].execution_arn}/*/POST/v1/results"
}
