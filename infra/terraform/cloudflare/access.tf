resource "cloudflare_zero_trust_access_identity_provider" "otp" {
  count = local.access_enabled ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = "Plntir email one-time PIN"
  type       = "onetimepin"
  config     = {}
}

# WARP alone also matches the consumer client. requiring gateway at the same
# time binds access to a client connected to this zero trust organization.
resource "cloudflare_zero_trust_device_posture_rule" "warp" {
  count = local.access_enabled ? 1 : 0

  account_id  = var.cloudflare_account_id
  name        = "Plntir WARP connected"
  description = "Requires the Cloudflare One Client to be connected; combined with the Gateway rule below."
  type        = "warp"
  expiration  = "5m"
}

resource "cloudflare_zero_trust_device_posture_rule" "gateway" {
  count = local.access_enabled ? 1 : 0

  account_id  = var.cloudflare_account_id
  name        = "Plntir Zero Trust organization"
  description = "Requires the client to be connected to this Plntir Zero Trust instance."
  type        = "gateway"
  expiration  = "5m"
}

resource "cloudflare_zero_trust_access_application" "admin" {
  count = local.access_enabled ? 1 : 0

  account_id                  = var.cloudflare_account_id
  name                        = "Plntir administration"
  type                        = "self_hosted"
  destinations                = [{ type = "public", uri = "admin.plntir.example" }]
  session_duration            = "1h"
  allowed_idps                = [cloudflare_zero_trust_access_identity_provider.otp[0].id]
  auto_redirect_to_identity   = true
  allow_authenticate_via_warp = false
  enable_binding_cookie       = true
  http_only_cookie_attribute  = true
  same_site_cookie_attribute  = "strict"
  path_cookie_attribute       = true
  allow_iframe                = false
  options_preflight_bypass    = false
  app_launcher_visible        = false

  mfa_config = {
    mfa_disabled           = false
    allowed_authenticators = ["security_key"]
    session_duration       = "1h"
  }

  policies = [{
    name       = "Exact admin identity on enrolled WARP device"
    precedence = 1
    decision   = "allow"
    include = [{
      email = { email = var.admin_email }
    }]
    require = [
      { device_posture = { integration_uid = cloudflare_zero_trust_device_posture_rule.warp[0].id } },
      { device_posture = { integration_uid = cloudflare_zero_trust_device_posture_rule.gateway[0].id } },
    ]
  }]
}

resource "cloudflare_zero_trust_access_application" "fileshare" {
  count = local.access_enabled ? 1 : 0

  account_id                  = var.cloudflare_account_id
  name                        = "Plntir fileshare"
  type                        = "self_hosted"
  destinations                = [{ type = "public", uri = "plntir.example" }]
  session_duration            = "1h"
  allowed_idps                = [cloudflare_zero_trust_access_identity_provider.otp[0].id]
  auto_redirect_to_identity   = true
  allow_authenticate_via_warp = true
  enable_binding_cookie       = true
  http_only_cookie_attribute  = true
  same_site_cookie_attribute  = "strict"
  path_cookie_attribute       = true
  allow_iframe                = false
  options_preflight_bypass    = false
  app_launcher_visible        = false

  policies = [{
    name       = "Enrolled Plntir WARP devices only"
    precedence = 1
    decision   = "allow"
    include = [{
      everyone = {}
    }]
    require = [
      { device_posture = { integration_uid = cloudflare_zero_trust_device_posture_rule.warp[0].id } },
      { device_posture = { integration_uid = cloudflare_zero_trust_device_posture_rule.gateway[0].id } },
    ]
  }]
}
