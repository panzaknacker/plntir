#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)

terraform -chdir="$root/infra/terraform/aws" fmt -check
terraform -chdir="$root/infra/terraform/aws" init -backend=false -input=false >/dev/null
terraform -chdir="$root/infra/terraform/aws" validate
terraform -chdir="$root/infra/terraform/aws" test -no-color

terraform -chdir="$root/infra/terraform/cloudflare" fmt -check
terraform -chdir="$root/infra/terraform/cloudflare" init -backend=false -input=false >/dev/null
terraform -chdir="$root/infra/terraform/cloudflare" validate
terraform -chdir="$root/infra/terraform/cloudflare" test -no-color

if rg -n '(cloudflare_zero_trust_tunnel_cloudflared_token|cloudflare_zero_trust_access_service_token|cloudflared_token|tunnel_token|api_token\s*=)' "$root/infra/terraform" --glob '*.tf'; then
    printf '%s\n' 'FAIL: a credential-like Terraform field would enter state' >&2
    exit 1
fi

printf '%s\n' 'PASS Terraform formatting, schemas, offline plans, and no-state-secret invariants'
