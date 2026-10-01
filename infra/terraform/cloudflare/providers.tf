provider "cloudflare" {
  # authentication is read from CLOUDFLARE_API_TOKEN at runtime. never add a
  # token variable: terraform variables and state are not a secret boundary.
}
