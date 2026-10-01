locals {
  compute_names = {
    core  = "plntir-core-01"
    mdm   = "plntir-mdm-01"
    siem  = "plntir-siem-01"
    edge  = "plntir-edge-01"
    relay = "plntir-relay-01"
  }

  ec2_architectures = {
    core  = "amd64"
    mdm   = "amd64"
    siem  = "amd64"
    edge  = "amd64"
    relay = "arm64"
  }

  ec2_root_volume_gib = {
    core  = 60
    mdm   = 60
    siem  = 320
    edge  = 20
    relay = 8
  }

  ec2_subnet_slot = {
    core  = "a"
    mdm   = "b"
    siem  = "a"
    edge  = "a"
    relay = "b"
  }

  selected_ami_ids = local.compute_enabled ? (
    local.ec2_compute_enabled ? var.ec2_ami_ids : { arm64 = var.lightsail_relay_ami_id }
  ) : {}

  ec2_nodes = local.ec2_compute_enabled ? {
    for role, name in local.compute_names : role => {
      name            = name
      architecture    = local.ec2_architectures[role]
      instance_type   = var.ec2_instance_types[role]
      root_volume_gib = local.ec2_root_volume_gib[role]
      subnet_slot     = local.ec2_subnet_slot[role]
      key_pair_name   = var.ec2_key_pair_names[role]
    }
  } : {}
}

resource "terraform_data" "compute_gate" {
  count = local.compute_enabled ? 1 : 0

  input = {
    approval_reference = var.immediate_approval_reference
    compute_strategy   = var.compute_strategy
    ec2_architecture   = var.ec2_zero_ingress_architecture_approved
    ec2_transport      = var.ec2_outbound_transport_proof_sha256
    price_checked_at   = var.price_checked_at
    price_report       = var.price_report_sha256
    release            = var.compute_release_id
    monthly_estimate   = var.approved_vm_monthly_estimate_usd
  }

  lifecycle {
    precondition {
      condition = (
        var.compute_strategy == "accept_transient_lightsail_defaults" ||
        var.compute_strategy == "ec2_zero_ingress"
      )
      error_message = "Compute requires an explicit transient-Lightsail or zero-ingress-EC2 strategy."
    }
    precondition {
      condition = !local.ec2_compute_enabled || (
        var.ec2_zero_ingress_architecture_approved &&
        var.ec2_outbound_transport_proof_sha256 != ""
      )
      error_message = "EC2 zero-ingress is blocked until a revised outbound transport/recovery architecture and its signed qualification report are explicitly approved."
    }
    precondition {
      condition = (
        var.price_checked_at != "" &&
        var.price_report_sha256 != "" &&
        var.approved_vm_monthly_estimate_usd > 0 &&
        var.approved_vm_monthly_estimate_usd <= var.vm_monthly_budget_usd
      )
      error_message = "Compute requires a reviewed current-price report below the USD 150 steady-state limit."
    }
    precondition {
      condition = (
        timecmp(var.price_checked_at, timestamp()) <= 0 &&
        timecmp(timestamp(), timeadd(var.price_checked_at, "4h")) <= 0
      )
      error_message = "The price/catalog report must be no more than four hours old when apply executes."
    }
    precondition {
      condition     = var.compute_release_id != ""
      error_message = "Compute requires a signed immutable release digest."
    }
    precondition {
      condition     = var.service_role_permissions_boundary_arn != ""
      error_message = "Compute service roles require the immutable root-bootstrap permissions boundary."
    }
    precondition {
      condition = !local.lightsail_compute_enabled || (
        toset(keys(var.lightsail_node_specs)) == toset(["core", "mdm", "siem", "edge"]) &&
        var.lightsail_peer_vpc_id != "" &&
        var.lightsail_relay_subnet_id != "" &&
        var.lightsail_relay_availability_zone != "" &&
        var.lightsail_relay_ami_id != "" &&
        var.lightsail_relay_key_pair_name != "" &&
        var.lightsail_node_specs["edge"].availability_zone != var.lightsail_relay_availability_zone
      )
      error_message = "The Lightsail strategy requires four exact catalog specs, default-VPC relay inputs, and separate edge/relay zones."
    }
    precondition {
      condition = !local.ec2_compute_enabled || (
        length(var.ec2_availability_zones) == 2 &&
        toset(keys(var.ec2_ami_ids)) == toset(["amd64", "arm64"]) &&
        toset(keys(var.ec2_key_pair_names)) == toset(["core", "mdm", "siem", "edge", "relay"])
      )
      error_message = "The EC2 strategy requires two zones, two exact Canonical AMIs, and five distinct node key pairs."
    }
  }
}

data "aws_ami" "compute" {
  for_each = local.selected_ami_ids

  owners      = ["099720109477"]
  most_recent = false

  filter {
    name   = "image-id"
    values = [each.value]
  }

  filter {
    name   = "architecture"
    values = [each.key == "arm64" ? "arm64" : "x86_64"]
  }

  filter {
    name = "name"
    values = each.key == "arm64" ? [
      "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*",
      "ubuntu/images/hvm-ssd/ubuntu-noble-24.04-arm64-server-*",
      ] : [
      "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
      "ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*",
    ]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_iam_role" "relay_ssm" {
  count = local.compute_enabled ? 1 : 0

  name                 = "plntir-relay-ssm"
  path                 = "/plntir/service/"
  max_session_duration = 3600
  permissions_boundary = var.service_role_permissions_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EC2Only"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name    = "plntir-relay-ssm"
    Purpose = "fido-owner-ssm-recovery"
  }
}

resource "aws_iam_role_policy_attachment" "relay_ssm" {
  count = local.compute_enabled ? 1 : 0

  role       = aws_iam_role.relay_ssm[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "relay_ssm" {
  count = local.compute_enabled ? 1 : 0

  name = "plntir-relay-ssm"
  path = "/plntir/"
  role = aws_iam_role.relay_ssm[0].name
}

resource "aws_lightsail_instance" "node" {
  for_each = local.lightsail_compute_enabled ? var.lightsail_node_specs : {}

  name              = local.compute_names[each.key]
  availability_zone = each.value.availability_zone
  blueprint_id      = each.value.blueprint_id
  bundle_id         = each.value.bundle_id
  key_pair_name     = each.value.key_pair_name
  ip_address_type   = each.value.ip_address_type
  user_data = join("\n", [
    "#!/bin/sh",
    "set -eu",
    "hostnamectl set-hostname ${local.compute_names[each.key]}",
    "install -d -m 0700 /etc/plntir",
    "printf '%s\\n' 'schema_version=1' 'role=${each.key}' 'release=${var.compute_release_id}' > /etc/plntir/bootstrap-node",
    "chmod 0600 /etc/plntir/bootstrap-node",
  ])

  tags = {
    Name          = local.compute_names[each.key]
    NodeRole      = each.key
    NetworkIntent = "outbound-only-after-immediate-port-seal"
    Release       = var.compute_release_id
  }

  depends_on = [terraform_data.compute_gate]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "lightsail_relay" {
  count = local.lightsail_compute_enabled ? 1 : 0

  name        = "plntir-relay-zero-ingress"
  description = "Plntir relay: deliberately no inbound rules"
  vpc_id      = var.lightsail_peer_vpc_id
  ingress     = []

  egress {
    description = "Outbound connector, SSM, S3 and update traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name          = "plntir-relay-zero-ingress"
    NodeRole      = "relay"
    InboundPolicy = "empty"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "lightsail_relay" {
  count = local.lightsail_compute_enabled ? 1 : 0

  ami                         = data.aws_ami.compute["arm64"].id
  instance_type               = "t4g.nano"
  availability_zone           = var.lightsail_relay_availability_zone
  subnet_id                   = var.lightsail_relay_subnet_id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.lightsail_relay[0].id]
  iam_instance_profile        = aws_iam_instance_profile.relay_ssm[0].name
  key_name                    = var.lightsail_relay_key_pair_name
  source_dest_check           = true
  disable_api_termination     = true
  monitoring                  = false
  user_data_replace_on_change = true
  user_data = join("\n", [
    "#!/bin/sh",
    "set -eu",
    "hostnamectl set-hostname ${local.compute_names.relay}",
    "install -d -m 0700 /etc/plntir",
    "printf '%s\\n' 'schema_version=1' 'role=relay' 'release=${var.compute_release_id}' > /etc/plntir/bootstrap-node",
    "chmod 0600 /etc/plntir/bootstrap-node",
    "systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true",
  ])

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }

  tags = {
    Name          = local.compute_names.relay
    NodeRole      = "relay"
    InboundPolicy = "empty"
    Release       = var.compute_release_id
  }

  depends_on = [aws_iam_role_policy_attachment.relay_ssm]

  lifecycle {
    prevent_destroy = true
  }
}

resource "terraform_data" "lightsail_public_port_seal" {
  count = local.lightsail_compute_enabled ? 1 : 0

  triggers_replace = [
    sha256(jsonencode(sort([for instance in values(aws_lightsail_instance.node) : instance.name]))),
    filesha256("${path.module}/scripts/seal-lightsail-network.sh"),
  ]

  provisioner "local-exec" {
    command = "${path.module}/scripts/seal-lightsail-network.sh"
    environment = {
      PLNTIR_AWS_ACCOUNT_ID                = var.aws_account_id
      PLNTIR_EXPECTED_DEFAULT_VPC_ID       = var.lightsail_peer_vpc_id
      PLNTIR_EXPECTED_RELAY_SUBNET_ID      = var.lightsail_relay_subnet_id
      PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON = jsonencode(sort([for instance in values(aws_lightsail_instance.node) : instance.name]))
      PLNTIR_PROTECTED_WATCH_ARN           = var.protected_watch_arn
      PLNTIR_REGION                        = var.region
      PLNTIR_SEAL_MODE                     = "ports"
    }
  }

  depends_on = [aws_lightsail_instance.node]
}

resource "terraform_data" "lightsail_network_seal" {
  count = local.lightsail_compute_enabled ? 1 : 0

  triggers_replace = [
    sha256(jsonencode(sort([for instance in values(aws_lightsail_instance.node) : instance.name]))),
    filesha256("${path.module}/scripts/seal-lightsail-network.sh"),
  ]

  provisioner "local-exec" {
    command = "${path.module}/scripts/seal-lightsail-network.sh"
    environment = {
      PLNTIR_AWS_ACCOUNT_ID                = var.aws_account_id
      PLNTIR_EXPECTED_DEFAULT_VPC_ID       = var.lightsail_peer_vpc_id
      PLNTIR_EXPECTED_RELAY_SUBNET_ID      = var.lightsail_relay_subnet_id
      PLNTIR_LIGHTSAIL_INSTANCE_NAMES_JSON = jsonencode(sort([for instance in values(aws_lightsail_instance.node) : instance.name]))
      PLNTIR_PROTECTED_WATCH_ARN           = var.protected_watch_arn
      PLNTIR_REGION                        = var.region
      PLNTIR_SEAL_MODE                     = "peer"
    }
  }

  depends_on = [terraform_data.lightsail_public_port_seal, aws_instance.lightsail_relay]
}

resource "aws_vpc" "zero_ingress" {
  count = local.ec2_compute_enabled ? 1 : 0

  cidr_block                       = "10.42.0.0/24"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  instance_tenancy                 = "default"

  tags = {
    Name          = "plntir-v1-zero-ingress"
    InboundPolicy = "security-groups-empty"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_internet_gateway" "zero_ingress" {
  count = local.ec2_compute_enabled ? 1 : 0

  vpc_id = aws_vpc.zero_ingress[0].id

  tags = { Name = "plntir-v1-egress" }
}

resource "aws_subnet" "zero_ingress" {
  for_each = local.ec2_compute_enabled ? { a = 0, b = 1 } : {}

  vpc_id                          = aws_vpc.zero_ingress[0].id
  availability_zone               = var.ec2_availability_zones[each.value]
  cidr_block                      = cidrsubnet(aws_vpc.zero_ingress[0].cidr_block, 1, each.value)
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.zero_ingress[0].ipv6_cidr_block, 8, each.value)
  assign_ipv6_address_on_creation = false
  map_public_ip_on_launch         = false

  tags = {
    Name = "plntir-v1-${each.key}"
  }
}

resource "aws_route_table" "zero_ingress" {
  for_each = aws_subnet.zero_ingress

  vpc_id = aws_vpc.zero_ingress[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.zero_ingress[0].id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.zero_ingress[0].id
  }

  tags = { Name = "plntir-v1-${each.key}-egress" }
}

resource "aws_route_table_association" "zero_ingress" {
  for_each = aws_subnet.zero_ingress

  subnet_id      = each.value.id
  route_table_id = aws_route_table.zero_ingress[each.key].id
}

resource "aws_security_group" "zero_ingress" {
  for_each = local.ec2_nodes

  name        = "${each.value.name}-zero-ingress"
  description = "${each.value.name}: deliberately no inbound rules"
  vpc_id      = aws_vpc.zero_ingress[0].id
  ingress     = []

  egress {
    description = "Outbound connector and signed-update traffic over IPv4"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description      = "Outbound connector and signed-update traffic over IPv6"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name          = "${each.value.name}-zero-ingress"
    NodeRole      = each.key
    InboundPolicy = "empty"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "zero_ingress" {
  for_each = local.ec2_nodes

  ami                         = data.aws_ami.compute[each.value.architecture].id
  instance_type               = each.value.instance_type
  subnet_id                   = aws_subnet.zero_ingress[each.value.subnet_slot].id
  associate_public_ip_address = true
  ipv6_address_count          = 1
  vpc_security_group_ids      = [aws_security_group.zero_ingress[each.key].id]
  iam_instance_profile        = each.key == "relay" ? aws_iam_instance_profile.relay_ssm[0].name : null
  key_name                    = each.value.key_pair_name
  source_dest_check           = true
  disable_api_termination     = true
  monitoring                  = false
  user_data_replace_on_change = true
  user_data = join("\n", [
    "#!/bin/sh",
    "set -eu",
    "hostnamectl set-hostname ${each.value.name}",
    "install -d -m 0700 /etc/plntir",
    "printf '%s\\n' 'schema_version=1' 'role=${each.key}' 'release=${var.compute_release_id}' > /etc/plntir/bootstrap-node",
    "chmod 0600 /etc/plntir/bootstrap-node",
    each.key == "relay" ? "systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true" : ":",
  ])

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = each.value.root_volume_gib
    volume_type           = "gp3"
  }

  tags = {
    Name          = each.value.name
    NodeRole      = each.key
    InboundPolicy = "empty"
    Release       = var.compute_release_id
  }

  depends_on = [aws_iam_role_policy_attachment.relay_ssm, aws_route_table_association.zero_ingress]

  lifecycle {
    prevent_destroy = true
  }
}
