# Both providers read their token from the environment when the var is null, so
# secrets never land in a tfvars file or in state input:
#   DIGITALOCEAN_TOKEN      — DO API token (Droplets/VPC/Firewall/Project)
#   CLOUDFLARE_API_TOKEN    — CF API token (DNS:Edit, Load Balancing:Edit, Zone:Read, Calls:Edit)

provider "digitalocean" {
  token = var.do_token # null => falls back to DIGITALOCEAN_TOKEN
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token # null => falls back to CLOUDFLARE_API_TOKEN
}

# Resolve the zone id from its name so nothing hardcodes an opaque id.
data "cloudflare_zone" "this" {
  name = var.zone_name
}
