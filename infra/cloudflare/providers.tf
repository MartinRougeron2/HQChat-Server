# The provider reads the API token from the CLOUDFLARE_API_TOKEN environment
# variable when `api_token` is null — so the secret is NEVER written to a
# tfvars file or state input. In CI it comes from a GitHub Actions secret.
#
# Token scopes (create a scoped token, not a global key):
#   Zone   → DNS:Edit, Zone Settings:Edit, Zone:Read
#   Zone   → Workers Routes:Edit, Page Rules:Edit (if used)
#   Account→ Workers Scripts:Edit
#   Zone   → Health Checks:Edit  (if enable_health_check)
#   Account→ Account Settings:Read, Notifications:Edit (if enable_health_check)

provider "cloudflare" {
  api_token = var.cloudflare_api_token # null => falls back to CLOUDFLARE_API_TOKEN
}

# Resolve the zone id (and account) from the zone name so the rest of the
# module never hardcodes an opaque id.
data "cloudflare_zone" "this" {
  name = var.zone_name
}
