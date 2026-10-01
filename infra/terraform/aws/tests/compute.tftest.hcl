mock_provider "aws" {}

run "compute_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(aws_lightsail_instance.node) == 0 &&
      length(aws_instance.lightsail_relay) == 0 &&
      length(aws_instance.zero_ingress) == 0 &&
      length(aws_vpc.zero_ingress) == 0 &&
      length(terraform_data.lightsail_public_port_seal) == 0 &&
      length(terraform_data.lightsail_network_seal) == 0
    )
    error_message = "The default plan must contain no new compute or network-seal action."
  }

  assert {
    condition     = output.compute_runtime == null
    error_message = "Disabled compute runtime output must be null."
  }
}

run "lightsail_topology_requires_immediate_network_seal" {
  command = plan

  variables {
    cloud_mutations_authorized            = true
    immediate_approval_reference          = "approved-20260904T120000Z"
    compute_strategy                      = "accept_transient_lightsail_defaults"
    compute_stack_enabled                 = true
    price_checked_at                      = "2026-09-04T11:55:00Z"
    price_report_sha256                   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    approved_vm_monthly_estimate_usd      = 147.77
    compute_release_id                    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    service_role_permissions_boundary_arn = "arn:aws:iam::444455556666:policy/plntir/boundary/PlntirServiceBoundary"
    lightsail_peer_vpc_id                 = "vpc-0123456789abcdef0"
    lightsail_relay_subnet_id             = "subnet-0123456789abcdef0"
    lightsail_relay_availability_zone     = "eu-central-1b"
    lightsail_relay_ami_id                = "ami-0123456789abcdef0"
    lightsail_relay_key_pair_name         = "plntir-relay-01"
    lightsail_node_specs = {
      core = {
        availability_zone = "eu-central-1a"
        blueprint_id      = "ubuntu_24_04"
        bundle_id         = "reviewed-core-bundle"
        key_pair_name     = "plntir-core-01"
        ip_address_type   = "dualstack"
      }
      mdm = {
        availability_zone = "eu-central-1b"
        blueprint_id      = "ubuntu_24_04"
        bundle_id         = "reviewed-mdm-bundle"
        key_pair_name     = "plntir-mdm-01"
        ip_address_type   = "dualstack"
      }
      siem = {
        availability_zone = "eu-central-1a"
        blueprint_id      = "ubuntu_24_04"
        bundle_id         = "reviewed-siem-bundle"
        key_pair_name     = "plntir-siem-01"
        ip_address_type   = "dualstack"
      }
      edge = {
        availability_zone = "eu-central-1a"
        blueprint_id      = "ubuntu_24_04"
        bundle_id         = "reviewed-edge-bundle"
        key_pair_name     = "plntir-edge-01"
        ip_address_type   = "ipv6"
      }
    }
  }

  assert {
    condition = (
      length(aws_lightsail_instance.node) == 4 &&
      length(aws_instance.lightsail_relay) == 1 &&
      length(terraform_data.lightsail_public_port_seal) == 1 &&
      length(terraform_data.lightsail_network_seal) == 1 &&
      length(aws_instance.zero_ingress) == 0
    )
    error_message = "The Lightsail strategy must create four Lightsail nodes, one EC2 relay, and one mandatory network seal."
  }

  assert {
    condition = (
      aws_lightsail_instance.node["edge"].ip_address_type == "ipv6" &&
      alltrue([
        for role in ["core", "mdm", "siem"] :
        aws_lightsail_instance.node[role].ip_address_type == "dualstack"
      ])
    )
    error_message = "Only the Lightsail edge node may use the v1 IPv6-only bundle."
  }

  assert {
    condition = (
      length(aws_security_group.lightsail_relay[0].ingress) == 0 &&
      aws_instance.lightsail_relay[0].instance_type == "t4g.nano" &&
      aws_instance.lightsail_relay[0].metadata_options[0].http_tokens == "required" &&
      aws_instance.lightsail_relay[0].root_block_device[0].volume_size == 8
    )
    error_message = "The Lightsail relay must retain zero ingress, IMDSv2, t4g.nano, and an encrypted 8-GiB root volume."
  }
}

run "ec2_topology_has_zero_ingress_from_launch" {
  command = plan

  variables {
    cloud_mutations_authorized             = true
    immediate_approval_reference           = "approved-20260904T121500Z"
    compute_strategy                       = "ec2_zero_ingress"
    ec2_zero_ingress_architecture_approved = true
    ec2_outbound_transport_proof_sha256    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    compute_stack_enabled                  = true
    price_checked_at                       = "2026-09-04T12:10:00Z"
    price_report_sha256                    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    approved_vm_monthly_estimate_usd       = 149.00
    compute_release_id                     = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    service_role_permissions_boundary_arn  = "arn:aws:iam::444455556666:policy/plntir/boundary/PlntirServiceBoundary"
    ec2_availability_zones                 = ["eu-central-1a", "eu-central-1b"]
    ec2_ami_ids = {
      amd64 = "ami-0123456789abcdef0"
      arm64 = "ami-0fedcba9876543210"
    }
    ec2_key_pair_names = {
      core  = "plntir-core-01"
      mdm   = "plntir-mdm-01"
      siem  = "plntir-siem-01"
      edge  = "plntir-edge-01"
      relay = "plntir-relay-01"
    }
  }

  assert {
    condition = (
      length(aws_instance.zero_ingress) == 5 &&
      length(aws_security_group.zero_ingress) == 5 &&
      length(aws_lightsail_instance.node) == 0 &&
      length(terraform_data.lightsail_public_port_seal) == 0 &&
      length(terraform_data.lightsail_network_seal) == 0
    )
    error_message = "The EC2 strategy must create exactly five EC2 nodes and no Lightsail resource."
  }

  assert {
    condition = alltrue([
      for group in values(aws_security_group.zero_ingress) :
      length(group.ingress) == 0
    ])
    error_message = "Every EC2 node security group must have an empty ingress set."
  }

  assert {
    condition = alltrue([
      for instance in values(aws_instance.zero_ingress) :
      instance.metadata_options[0].http_tokens == "required" &&
      instance.root_block_device[0].encrypted == true &&
      instance.root_block_device[0].volume_type == "gp3"
    ])
    error_message = "Every EC2 node must require IMDSv2 and an encrypted gp3 root volume."
  }

  assert {
    condition = (
      local.ec2_subnet_slot["edge"] != local.ec2_subnet_slot["relay"] &&
      aws_instance.zero_ingress["relay"].iam_instance_profile == aws_iam_instance_profile.relay_ssm[0].name &&
      aws_iam_role.relay_ssm[0].permissions_boundary == var.service_role_permissions_boundary_arn &&
      aws_instance.zero_ingress["siem"].root_block_device[0].volume_size == 320
    )
    error_message = "Edge/relay separation, relay-only SSM, and SIEM storage sizing must remain explicit."
  }
}

run "ec2_topology_rejects_missing_outbound_transport_proof" {
  command = plan

  variables {
    cloud_mutations_authorized            = true
    immediate_approval_reference          = "approved-20260904T123000Z"
    compute_strategy                      = "ec2_zero_ingress"
    compute_stack_enabled                 = true
    price_checked_at                      = "2026-09-04T12:25:00Z"
    price_report_sha256                   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    approved_vm_monthly_estimate_usd      = 149.00
    compute_release_id                    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    service_role_permissions_boundary_arn = "arn:aws:iam::444455556666:policy/plntir/boundary/PlntirServiceBoundary"
    ec2_availability_zones                = ["eu-central-1a", "eu-central-1b"]
    ec2_ami_ids = {
      amd64 = "ami-0123456789abcdef0"
      arm64 = "ami-0fedcba9876543210"
    }
    ec2_key_pair_names = {
      core  = "plntir-core-01"
      mdm   = "plntir-mdm-01"
      siem  = "plntir-siem-01"
      edge  = "plntir-edge-01"
      relay = "plntir-relay-01"
    }
  }

  expect_failures = [terraform_data.compute_gate]
}
