mock_provider "cloudflare" {}

run "access_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(cloudflare_zero_trust_access_identity_provider.otp) == 0 &&
      length(cloudflare_zero_trust_device_posture_rule.warp) == 0 &&
      length(cloudflare_zero_trust_device_posture_rule.gateway) == 0 &&
      length(cloudflare_zero_trust_access_application.admin) == 0 &&
      length(cloudflare_zero_trust_access_application.fileshare) == 0
    )
    error_message = "The default Cloudflare plan must not create Access or posture resources."
  }
}

run "access_topology_is_device_bound" {
  command = plan

  variables {
    cloudflare_account_id                = "11111111111111111111111111111111"
    cloudflare_zone_id                   = "22222222222222222222222222222222"
    cloud_mutations_authorized           = true
    immediate_approval_reference         = "approved-20260904T140000Z"
    access_stack_enabled                 = true
    admin_email                          = "admin@example.net"
    warp_enrollment_policy_verified      = true
    independent_mfa_entitlement_verified = true
  }

  override_resource {
    target          = cloudflare_zero_trust_access_identity_provider.otp[0]
    override_during = plan
    values          = { id = "00000000-0000-4000-8000-000000000001" }
  }

  override_resource {
    target          = cloudflare_zero_trust_device_posture_rule.warp[0]
    override_during = plan
    values          = { id = "00000000-0000-4000-8000-000000000002" }
  }

  override_resource {
    target          = cloudflare_zero_trust_device_posture_rule.gateway[0]
    override_during = plan
    values          = { id = "00000000-0000-4000-8000-000000000003" }
  }

  assert {
    condition = (
      length(cloudflare_zero_trust_access_identity_provider.otp) == 1 &&
      length(cloudflare_zero_trust_device_posture_rule.warp) == 1 &&
      length(cloudflare_zero_trust_device_posture_rule.gateway) == 1 &&
      length(cloudflare_zero_trust_access_application.admin) == 1 &&
      length(cloudflare_zero_trust_access_application.fileshare) == 1
    )
    error_message = "The approved Access plan must create one OTP IdP, two posture checks, and two applications."
  }

  assert {
    condition = (
      cloudflare_zero_trust_device_posture_rule.warp[0].type == "warp" &&
      cloudflare_zero_trust_device_posture_rule.gateway[0].type == "gateway" &&
      cloudflare_zero_trust_device_posture_rule.warp[0].expiration == "5m" &&
      cloudflare_zero_trust_access_application.admin[0].session_duration == "1h" &&
      cloudflare_zero_trust_access_application.admin[0].mfa_config.allowed_authenticators[0] == "security_key" &&
      cloudflare_zero_trust_access_application.admin[0].mfa_config.mfa_disabled == false
    )
    error_message = "Admin Access must require current device posture and hourly hardware-key MFA."
  }

  assert {
    condition = (
      cloudflare_zero_trust_access_application.admin[0].allow_authenticate_via_warp == false &&
      cloudflare_zero_trust_access_application.fileshare[0].allow_authenticate_via_warp == true &&
      cloudflare_zero_trust_access_application.admin[0].enable_binding_cookie &&
      cloudflare_zero_trust_access_application.fileshare[0].same_site_cookie_attribute == "strict" &&
      cloudflare_zero_trust_access_application.admin[0].destinations[0].uri == "admin.plntir.example" &&
      cloudflare_zero_trust_access_application.fileshare[0].destinations[0].uri == "plntir.example"
    )
    error_message = "Access application authentication, cookie, or hostname invariants drifted."
  }

  assert {
    condition = (
      length(cloudflare_zero_trust_access_application.admin[0].policies[0].require) == 2 &&
      length(cloudflare_zero_trust_access_application.fileshare[0].policies[0].require) == 2 &&
      tolist(cloudflare_zero_trust_access_application.admin[0].policies[0].include)[0].email.email == "admin@example.net" &&
      toset([
        for rule in cloudflare_zero_trust_access_application.admin[0].policies[0].require :
        rule.device_posture.integration_uid
        ]) == toset([
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003",
      ])
    )
    error_message = "The exact admin email and both organization-bound posture checks must be required."
  }
}

run "access_requires_enrollment_seal" {
  command = plan

  variables {
    cloudflare_account_id                = "11111111111111111111111111111111"
    cloudflare_zone_id                   = "22222222222222222222222222222222"
    cloud_mutations_authorized           = true
    immediate_approval_reference         = "approved-20260904T140000Z"
    access_stack_enabled                 = true
    admin_email                          = "admin@example.net"
    independent_mfa_entitlement_verified = true
  }

  expect_failures = [terraform_data.mutation_gate]
}

run "access_requires_mfa_entitlement" {
  command = plan

  variables {
    cloudflare_account_id           = "11111111111111111111111111111111"
    cloudflare_zone_id              = "22222222222222222222222222222222"
    cloud_mutations_authorized      = true
    immediate_approval_reference    = "approved-20260904T140000Z"
    access_stack_enabled            = true
    admin_email                     = "admin@example.net"
    warp_enrollment_policy_verified = true
  }

  expect_failures = [terraform_data.mutation_gate]
}

run "admin_email_must_be_canonical" {
  command = plan

  variables {
    admin_email = "Admin@Example.net"
  }

  expect_failures = [var.admin_email]
}
