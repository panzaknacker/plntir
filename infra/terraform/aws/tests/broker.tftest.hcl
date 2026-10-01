mock_provider "aws" {}

run "disabled_by_default" {
  command = plan

  assert {
    condition     = length(aws_kms_key.file_deks) == 0 && length(aws_lambda_function.kms_broker) == 0
    error_message = "The default plan must not create broker resources."
  }

  assert {
    condition     = output.scan_broker_runtime == null
    error_message = "Disabled broker runtime output must be null."
  }
}

run "enabled_topology_is_closed_and_bounded" {
  command = plan

  variables {
    cloud_mutations_authorized            = true
    immediate_approval_reference          = "approved-20260904T120000Z"
    compute_strategy                      = "ec2_zero_ingress"
    broker_stack_enabled                  = true
    broker_domain_name                    = "scan-broker.invalid"
    broker_certificate_arn                = "arn:aws:acm:eu-central-1:444455556666:certificate/00000000-0000-4000-8000-000000000000"
    broker_truststore_uri                 = "s3://plntir-trust-444455556666/scanner/ca.pem"
    broker_truststore_version             = "mock/version+1=="
    scanner_client_cert_sha256            = "0000000000000000000000000000000000000000000000000000000000000000"
    core_scan_verify_key                  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    scanner_result_verify_key             = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    cloudflare_account_id                 = "00000000000000000000000000000000"
    r2_bucket_name                        = "plntir-files-test"
    core_rolesanywhere_ca_path            = "tests/fixtures/mock-public-ca.crt"
    core_rolesanywhere_issuer_cn          = "Plntir Terraform Mock CA"
    core_rolesanywhere_subject_cn         = "plntir-core-01"
    kms_broker_artifact_path              = "tests/fixtures/mock-public-ca.crt"
    scan_result_broker_artifact_path      = "tests/fixtures/mock-public-ca.crt"
    service_role_permissions_boundary_arn = "arn:aws:iam::444455556666:policy/plntir/boundary/PlntirServiceBoundary"
  }

  assert {
    condition = (
      length(aws_kms_key.file_deks) == 1 &&
      length(aws_kms_key.scan_results) == 1 &&
      length(aws_sqs_queue.scan_results) == 1 &&
      length(aws_sqs_queue.scan_result_dlq) == 1 &&
      length(aws_sqs_queue_redrive_allow_policy.scan_result_dlq) == 1 &&
      length(aws_lambda_function.kms_broker) == 1 &&
      length(aws_lambda_function.scan_result_broker) == 1 &&
      length(aws_apigatewayv2_route.kms_broker) == 1 &&
      length(aws_apigatewayv2_route.scan_result_broker) == 1 &&
      length(aws_rolesanywhere_profile.core) == 1
    )
    error_message = "The approved broker plan is missing a required resource."
  }

  assert {
    condition = alltrue([
      aws_iam_role.core_scan_result_consumer[0].permissions_boundary == var.service_role_permissions_boundary_arn,
      aws_iam_role.kms_broker[0].permissions_boundary == var.service_role_permissions_boundary_arn,
      aws_iam_role.scan_result_broker[0].permissions_boundary == var.service_role_permissions_boundary_arn,
    ])
    error_message = "Every broker runtime role must carry the root-bootstrap permissions boundary."
  }

  assert {
    condition = (
      aws_apigatewayv2_api.scan_brokers[0].disable_execute_api_endpoint &&
      aws_apigatewayv2_route.kms_broker[0].route_key == "POST /v1/rewrap" &&
      aws_apigatewayv2_route.scan_result_broker[0].route_key == "POST /v1/results"
    )
    error_message = "API Gateway must expose exactly the two intended mTLS routes without its default endpoint."
  }

  assert {
    condition = (
      aws_sqs_queue.scan_results[0].fifo_queue &&
      aws_sqs_queue.scan_results[0].max_message_size == 32768 &&
      aws_sqs_queue.scan_results[0].receive_wait_time_seconds == 20 &&
      aws_sqs_queue.scan_results[0].visibility_timeout_seconds == 120 &&
      aws_sqs_queue.scan_result_dlq[0].message_retention_seconds == 1209600
    )
    error_message = "The result queue must remain FIFO, bounded, long-polled, and fail to its DLQ."
  }

  assert {
    condition = (
      aws_lambda_function.kms_broker[0].reserved_concurrent_executions == 2 &&
      aws_lambda_function.scan_result_broker[0].reserved_concurrent_executions == 2 &&
      aws_lambda_function.kms_broker[0].architectures[0] == "arm64" &&
      aws_lambda_function.scan_result_broker[0].runtime == "provided.al2023"
    )
    error_message = "Both brokers must use bounded arm64 custom-runtime Lambdas."
  }

  assert {
    condition = (
      aws_iam_role.core_scan_result_consumer[0].max_session_duration == 3600 &&
      aws_rolesanywhere_profile.core[0].duration_seconds == 3600 &&
      length(aws_rolesanywhere_profile.core[0].role_arns) == 1
    )
    error_message = "The Core Roles Anywhere session must be one hour and authorize only one runtime role."
  }
}

run "rejects_plntir_broker_domain" {
  command = plan

  variables {
    broker_domain_name = "admin.plntir.example"
  }

  expect_failures = [var.broker_domain_name]
}
