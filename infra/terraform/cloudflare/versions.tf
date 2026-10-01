terraform {
  required_version = ">= 1.15.0, < 1.17.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.24.0"
    }
  }

  backend "s3" {}
}
