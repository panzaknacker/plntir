variable "aws_account_id" {
  description = "Exact AWS account selected during the read-only bootstrap inventory."
  type        = string
  default     = "444455556666"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be exactly 12 decimal digits."
  }
}

variable "region" {
  description = "Plntir v1 is deliberately confined to Frankfurt."
  type        = string
  default     = "eu-central-1"

  validation {
    condition     = var.region == "eu-central-1"
    error_message = "Plntir v1 may only be planned in eu-central-1."
  }
}

variable "protected_watch_arn" {
  description = "Exact pre-existing Watch ARN. It is inventory-only and never managed by this root."
  type        = string
  default     = "arn:aws:lightsail:eu-central-1:444455556666:Instance/e40d6806-5f0b-4cfd-8ee9-36ac8f5af13d"

  validation {
    condition     = can(regex("^arn:aws:lightsail:eu-central-1:[0-9]{12}:Instance/[0-9a-f-]{36}$", var.protected_watch_arn))
    error_message = "protected_watch_arn must be the exact eu-central-1 Lightsail instance ARN."
  }
}

variable "cloud_mutations_authorized" {
  description = "Fail-safe switch. Keep false for init, validate, cost reports, and read-only plans."
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

variable "compute_strategy" {
  description = <<-EOT
    Required before compute can be enabled. Lightsail creates default public
    SSH/HTTP rules non-atomically; EC2 can start with an empty security group.
  EOT
  type        = string
  default     = "unselected"

  validation {
    condition = contains([
      "unselected",
      "accept_transient_lightsail_defaults",
      "ec2_zero_ingress",
    ], var.compute_strategy)
    error_message = "Select unselected, accept_transient_lightsail_defaults, or ec2_zero_ingress."
  }
}

variable "ec2_zero_ingress_architecture_approved" {
  description = <<-EOT
    Separate architecture gate for the EC2 alternative. Empty EC2 security
    groups also block private Edge/Core, Relay/SIEM, and agent/SIEM traffic, so
    this may become true only after approving a per-node outbound transport
    and an AWS-independent-of-Cloudflare recovery revision.
  EOT
  type        = bool
  default     = false
}

variable "ec2_outbound_transport_proof_sha256" {
  description = <<-EOT
    SHA-256 of a signed qualification report proving service routing, node
    bootstrap, connector loss, and AWS recovery with all EC2 ingress sets
    empty. It is deliberately unavailable in the current shadow build.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.ec2_outbound_transport_proof_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.ec2_outbound_transport_proof_sha256))
    error_message = "ec2_outbound_transport_proof_sha256 must be 64 lower-case hexadecimal characters, or empty while EC2 is blocked."
  }
}

variable "vm_monthly_budget_usd" {
  description = "Hard architecture gate for steady-state VM estimates."
  type        = number
  default     = 150

  validation {
    condition     = var.vm_monthly_budget_usd > 0 && var.vm_monthly_budget_usd <= 150
    error_message = "The v1 steady-state VM budget may not exceed USD 150."
  }
}

variable "aws_service_monthly_budget_usd" {
  description = "Backups, S3, KMS, Lambda and SNS budget ceiling."
  type        = number
  default     = 50

  validation {
    condition     = var.aws_service_monthly_budget_usd > 0 && var.aws_service_monthly_budget_usd <= 50
    error_message = "The v1 AWS service budget may not exceed USD 50."
  }
}

variable "compute_stack_enabled" {
  description = "Declares the five new nodes only inside an approved mutation window; false leaves compute absent."
  type        = bool
  default     = false
}

variable "price_checked_at" {
  description = "UTC timestamp from the immediately preceding AWS/Lightsail price and bundle inventory."
  type        = string
  default     = ""

  validation {
    condition     = var.price_checked_at == "" || can(regex("^20[0-9]{2}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$", var.price_checked_at))
    error_message = "price_checked_at must be an RFC3339 UTC second or empty while compute is disabled."
  }
}

variable "price_report_sha256" {
  description = "SHA-256 of the reviewed, non-secret current-price and instance-catalog report."
  type        = string
  default     = ""

  validation {
    condition     = var.price_report_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.price_report_sha256))
    error_message = "price_report_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "approved_vm_monthly_estimate_usd" {
  description = "Reviewed monthly VM estimate for the selected compute strategy; excludes ancillary AWS services."
  type        = number
  default     = 0

  validation {
    condition     = var.approved_vm_monthly_estimate_usd >= 0 && var.approved_vm_monthly_estimate_usd <= 150
    error_message = "The reviewed steady-state VM estimate must remain between USD 0 and USD 150."
  }
}

variable "compute_release_id" {
  description = "Signed immutable release digest bound into every new node's first-boot marker."
  type        = string
  default     = ""

  validation {
    condition     = var.compute_release_id == "" || can(regex("^sha256:[a-f0-9]{64}$", var.compute_release_id))
    error_message = "compute_release_id must be sha256: followed by 64 lower-case hexadecimal characters."
  }
}

variable "service_role_permissions_boundary_arn" {
  description = "Root-bootstrap output applied to every builder-created Plntir service role."
  type        = string
  default     = ""

  validation {
    condition = var.service_role_permissions_boundary_arn == "" || var.service_role_permissions_boundary_arn == (
      "arn:aws:iam::${var.aws_account_id}:policy/plntir/boundary/PlntirServiceBoundary"
    )
    error_message = "Use the exact root-bootstrap PlntirServiceBoundary ARN, or leave it empty while all stacks are disabled."
  }
}

variable "lightsail_node_specs" {
  description = "Exact catalog results for core, mdm, siem, and edge after the Lightsail strategy is approved."
  type = map(object({
    availability_zone = string
    blueprint_id      = string
    bundle_id         = string
    key_pair_name     = string
    ip_address_type   = string
  }))
  default = {}

  validation {
    condition = length(var.lightsail_node_specs) == 0 || (
      toset(keys(var.lightsail_node_specs)) == toset(["core", "mdm", "siem", "edge"]) &&
      alltrue([
        for role, spec in var.lightsail_node_specs :
        can(regex("^eu-central-1[a-z]$", spec.availability_zone)) &&
        can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$", spec.blueprint_id)) &&
        can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$", spec.bundle_id)) &&
        can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$", spec.key_pair_name)) &&
        spec.ip_address_type == (role == "edge" ? "ipv6" : "dualstack")
      ])
    )
    error_message = "Lightsail specs must define exactly core/mdm/siem/edge; edge is IPv6-only and the other nodes are dual-stack."
  }
}

variable "lightsail_peer_vpc_id" {
  description = "Exact default VPC ID proven by read-only inventory for Lightsail peering."
  type        = string
  default     = ""

  validation {
    condition     = var.lightsail_peer_vpc_id == "" || can(regex("^vpc-[a-f0-9]{8,17}$", var.lightsail_peer_vpc_id))
    error_message = "lightsail_peer_vpc_id must be a concrete VPC ID, or empty while disabled."
  }
}

variable "lightsail_relay_subnet_id" {
  description = "Exact public subnet in the default VPC for the SSM relay."
  type        = string
  default     = ""

  validation {
    condition     = var.lightsail_relay_subnet_id == "" || can(regex("^subnet-[a-f0-9]{8,17}$", var.lightsail_relay_subnet_id))
    error_message = "lightsail_relay_subnet_id must be a concrete subnet ID, or empty while disabled."
  }
}

variable "lightsail_relay_availability_zone" {
  description = "Exact availability zone of the default-VPC relay subnet."
  type        = string
  default     = ""

  validation {
    condition     = var.lightsail_relay_availability_zone == "" || can(regex("^eu-central-1[a-z]$", var.lightsail_relay_availability_zone))
    error_message = "lightsail_relay_availability_zone must be in eu-central-1, or empty while disabled."
  }
}

variable "lightsail_relay_ami_id" {
  description = "Exact Canonical Ubuntu 24.04 arm64 AMI ID for the relay."
  type        = string
  default     = ""

  validation {
    condition     = var.lightsail_relay_ami_id == "" || can(regex("^ami-[a-f0-9]{8,17}$", var.lightsail_relay_ami_id))
    error_message = "lightsail_relay_ami_id must be a concrete AMI ID, or empty while disabled."
  }
}

variable "lightsail_relay_key_pair_name" {
  description = "Out-of-band imported Ed25519 key-pair name for relay recovery."
  type        = string
  default     = ""

  validation {
    condition     = var.lightsail_relay_key_pair_name == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$", var.lightsail_relay_key_pair_name))
    error_message = "lightsail_relay_key_pair_name must be a concrete EC2 key-pair name, or empty while disabled."
  }
}

variable "ec2_availability_zones" {
  description = "Two distinct Frankfurt availability zones; edge and relay are placed separately."
  type        = list(string)
  default     = []

  validation {
    condition = length(var.ec2_availability_zones) == 0 || (
      length(var.ec2_availability_zones) == 2 &&
      length(distinct(var.ec2_availability_zones)) == 2 &&
      alltrue([for zone in var.ec2_availability_zones : can(regex("^eu-central-1[a-z]$", zone))])
    )
    error_message = "ec2_availability_zones must contain exactly two distinct eu-central-1 zones, or be empty while disabled."
  }
}

variable "ec2_ami_ids" {
  description = "Exact Canonical Ubuntu 24.04 AMIs selected for the x86_64 and arm64 nodes."
  type        = map(string)
  default     = {}

  validation {
    condition = length(var.ec2_ami_ids) == 0 || (
      toset(keys(var.ec2_ami_ids)) == toset(["amd64", "arm64"]) &&
      alltrue([for id in values(var.ec2_ami_ids) : can(regex("^ami-[a-f0-9]{8,17}$", id))])
    )
    error_message = "ec2_ami_ids must contain concrete amd64 and arm64 AMI IDs, or be empty while disabled."
  }
}

variable "ec2_key_pair_names" {
  description = "Five out-of-band imported, node-specific Ed25519 key-pair names."
  type        = map(string)
  default     = {}

  validation {
    condition = length(var.ec2_key_pair_names) == 0 || (
      toset(keys(var.ec2_key_pair_names)) == toset(["core", "mdm", "siem", "edge", "relay"]) &&
      alltrue([for name in values(var.ec2_key_pair_names) : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$", name))]) &&
      length(distinct(values(var.ec2_key_pair_names))) == 5
    )
    error_message = "ec2_key_pair_names must contain five distinct concrete node key names, or be empty while disabled."
  }
}

variable "ec2_instance_types" {
  description = "v1 EC2 equivalents; changing this fixed floor is a new sizing and budget gate."
  type        = map(string)
  default = {
    core  = "t3.small"
    mdm   = "t3.small"
    siem  = "c7i-flex.xlarge"
    edge  = "t3.nano"
    relay = "t4g.nano"
  }

  validation {
    condition = (
      toset(keys(var.ec2_instance_types)) == toset(["core", "mdm", "siem", "edge", "relay"]) &&
      var.ec2_instance_types["core"] == "t3.small" &&
      var.ec2_instance_types["mdm"] == "t3.small" &&
      var.ec2_instance_types["siem"] == "c7i-flex.xlarge" &&
      var.ec2_instance_types["edge"] == "t3.nano" &&
      var.ec2_instance_types["relay"] == "t4g.nano"
    )
    error_message = "The v1 EC2 size floor is fixed; any change requires a reviewed architecture revision."
  }
}

variable "broker_stack_enabled" {
  description = "Creates the mTLS scan brokers, encrypted result queue, and Core Roles Anywhere identity only inside an approved mutation window."
  type        = bool
  default     = false
}

variable "broker_domain_name" {
  description = "Dedicated unproxied mTLS hostname. It must not be plntir.example or one of its subdomains."
  type        = string
  default     = ""

  validation {
    condition = var.broker_domain_name == "" || (
      can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.broker_domain_name)) &&
      var.broker_domain_name != "plntir.example" &&
      !endswith(var.broker_domain_name, ".plntir.example")
    )
    error_message = "broker_domain_name must be a lower-case non-plntir.example DNS hostname, or empty while disabled."
  }
}

variable "broker_certificate_arn" {
  description = "ACM certificate ARN for the dedicated regional API Gateway hostname."
  type        = string
  default     = ""

  validation {
    condition = var.broker_certificate_arn == "" || can(regex(
      "^arn:aws:acm:eu-central-1:[0-9]{12}:certificate/[0-9a-f-]{36}$",
      var.broker_certificate_arn,
    ))
    error_message = "broker_certificate_arn must identify an eu-central-1 ACM certificate, or be empty while disabled."
  }
}

variable "broker_truststore_uri" {
  description = "Versioned S3 URI containing only the public CA bundle accepted by API Gateway mTLS."
  type        = string
  default     = ""

  validation {
    condition = var.broker_truststore_uri == "" || can(regex(
      "^s3://plntir-[a-z0-9-]+-[0-9]{12}/[A-Za-z0-9!_.*'()/-]+\\.pem$",
      var.broker_truststore_uri,
    ))
    error_message = "broker_truststore_uri must be an s3://plntir-...-ACCOUNT/...pem URI, or empty while disabled."
  }
}

variable "broker_truststore_version" {
  description = "Immutable S3 VersionId of the public API Gateway mTLS truststore object."
  type        = string
  default     = ""

  validation {
    condition = var.broker_truststore_version == "" || (
      length(var.broker_truststore_version) <= 1024 &&
      can(regex("^[!-~]+$", var.broker_truststore_version))
    )
    error_message = "broker_truststore_version must be a non-secret printable ASCII S3 VersionId without whitespace, or empty while disabled."
  }
}

variable "scanner_client_cert_sha256" {
  description = "Lower-case SHA-256 fingerprint of the scanner's short-lived mTLS leaf certificate."
  type        = string
  default     = ""

  validation {
    condition     = var.scanner_client_cert_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.scanner_client_cert_sha256))
    error_message = "scanner_client_cert_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "core_scan_verify_key" {
  description = "Canonical unpadded base64url Ed25519 public key used to verify scan-job metadata. Never provide the signing key here."
  type        = string
  default     = ""

  validation {
    condition     = var.core_scan_verify_key == "" || can(regex("^[A-Za-z0-9_-]{43}$", var.core_scan_verify_key))
    error_message = "core_scan_verify_key must be a canonical 32-byte unpadded base64url public key, or empty while disabled."
  }
}

variable "scanner_result_verify_key" {
  description = "Canonical unpadded base64url Ed25519 public key used by the result broker and Core consumer."
  type        = string
  default     = ""

  validation {
    condition     = var.scanner_result_verify_key == "" || can(regex("^[A-Za-z0-9_-]{43}$", var.scanner_result_verify_key))
    error_message = "scanner_result_verify_key must be a canonical 32-byte unpadded base64url public key, or empty while disabled."
  }
}

variable "cloudflare_account_id" {
  description = "Cloudflare account bound into signed scan jobs; this is an identifier, not a token."
  type        = string
  default     = ""

  validation {
    condition     = var.cloudflare_account_id == "" || can(regex("^[a-f0-9]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be 32 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "r2_bucket_name" {
  description = "Exact R2 bucket bound into the scan-job signature and KMS broker."
  type        = string
  default     = ""

  validation {
    condition     = var.r2_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.r2_bucket_name))
    error_message = "r2_bucket_name must be a 3-63 character lower-case bucket name, or empty while disabled."
  }
}

variable "core_rolesanywhere_ca_path" {
  description = "Local path to the public PEM CA certificate for the Core runtime identity. Private keys must never enter Terraform."
  type        = string
  default     = ""
}

variable "core_rolesanywhere_issuer_cn" {
  description = "Exact X.509 issuer common name required by the Core role trust policy."
  type        = string
  default     = ""

  validation {
    condition     = var.core_rolesanywhere_issuer_cn == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,63}$", var.core_rolesanywhere_issuer_cn))
    error_message = "core_rolesanywhere_issuer_cn must be a bounded printable common name, or empty while disabled."
  }
}

variable "core_rolesanywhere_subject_cn" {
  description = "Exact X.509 subject common name authorized to consume scan results."
  type        = string
  default     = "plntir-core-01"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,63}$", var.core_rolesanywhere_subject_cn))
    error_message = "core_rolesanywhere_subject_cn must be a bounded printable common name."
  }
}

variable "kms_broker_artifact_path" {
  description = "Path to the deterministic arm64 KMS broker Lambda ZIP."
  type        = string
  default     = "../../../bin/plntir-kms-broker-arm64.zip"
}

variable "scan_result_broker_artifact_path" {
  description = "Path to the deterministic arm64 scan-result broker Lambda ZIP."
  type        = string
  default     = "../../../bin/plntir-scan-result-broker-arm64.zip"
}

variable "wazuh_integrity_stack_enabled" {
  description = "Creates only the isolated Wazuh Object-Lock/SNS/Roles-Anywhere integrity plane after its separate last-stage gate."
  type        = bool
  default     = false
}

variable "wazuh_last_stage_approved" {
  description = "Separate acknowledgement that Wazuh is being created last and the refreshed steady-state VM total remains below USD 150."
  type        = bool
  default     = false
}

variable "wazuh_siem_qualification_sha256" {
  description = "SHA-256 of the signed SIEM sizing, isolation, recovery, and below-budget qualification report."
  type        = string
  default     = ""

  validation {
    condition     = var.wazuh_siem_qualification_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.wazuh_siem_qualification_sha256))
    error_message = "wazuh_siem_qualification_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "wazuh_release_version" {
  description = "Exact reviewed Wazuh offline release. Changing it is a new release and qualification gate."
  type        = string
  default     = "4.14.7"

  validation {
    condition     = var.wazuh_release_version == "4.14.7"
    error_message = "The v1 Wazuh release is pinned to exactly 4.14.7."
  }
}

variable "wazuh_offline_bundle_sha256" {
  description = "SHA-256 of the reviewed amd64 Wazuh 4.14.7 offline bundle."
  type        = string
  default     = ""

  validation {
    condition     = var.wazuh_offline_bundle_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.wazuh_offline_bundle_sha256))
    error_message = "wazuh_offline_bundle_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "wazuh_release_attestation_sha256" {
  description = "SHA-256 of the signed manifest binding the installer, offline bundle, generated install files, version, and architecture."
  type        = string
  default     = ""

  validation {
    condition     = var.wazuh_release_attestation_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.wazuh_release_attestation_sha256))
    error_message = "wazuh_release_attestation_sha256 must be 64 lower-case hexadecimal characters, or empty while disabled."
  }
}

variable "wazuh_rolesanywhere_ca_path" {
  description = "Local path to the public PEM CA for the SIEM runtime identity. The private CA and leaf key remain outside Terraform."
  type        = string
  default     = ""
}

variable "wazuh_rolesanywhere_issuer_cn" {
  description = "Exact X.509 issuer common name accepted by the SIEM Roles Anywhere role."
  type        = string
  default     = ""

  validation {
    condition     = var.wazuh_rolesanywhere_issuer_cn == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9 .:_-]{0,63}$", var.wazuh_rolesanywhere_issuer_cn))
    error_message = "wazuh_rolesanywhere_issuer_cn must be a bounded printable common name, or empty while disabled."
  }
}

variable "wazuh_rolesanywhere_subject_cn" {
  description = "Exact X.509 subject common name authorized to append Wazuh integrity objects and publish alerts."
  type        = string
  default     = "plntir-siem-01"

  validation {
    condition     = var.wazuh_rolesanywhere_subject_cn == "plntir-siem-01"
    error_message = "The v1 Wazuh runtime certificate must be bound to plntir-siem-01."
  }
}

variable "wazuh_alert_routes_qualified" {
  description = "Seal marker set only after out-of-band email and SMS subscriptions have both delivered an independent test alert."
  type        = bool
  default     = false
}
