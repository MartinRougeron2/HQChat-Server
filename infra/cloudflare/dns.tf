locals {
  zone_id = data.cloudflare_zone.this.id

  app_fqdn     = "${var.app_host}.${var.zone_name}"
  preprod_fqdn = var.preprod_host == null ? null : "${var.preprod_host}.${var.zone_name}"
}

# NOTE: example.com is a SHARED zone. Terraform here manages ONLY the
# DissQus records (chat + preprod.chat). The apex, www, backend, bbia, yt and
# the MX/TXT email records are other projects' and are intentionally left
# unmanaged so an apply can never clobber them.

# --- App / API origin (chat.<zone>) → the VM, proxied (orange cloud) ----------
# This record ALREADY EXISTS in the zone (chat → the production droplet). Import
# it before the first apply (see README) so Terraform adopts it instead of
# erroring on create. The address itself lives in terraform.tfvars, which is not
# committed: behind an orange cloud the origin IP is a credential of sorts, and
# publishing it is how someone talks to nginx without passing the WAF.
resource "cloudflare_record" "app" {
  zone_id = local.zone_id
  name    = var.app_host
  type    = "A"
  value   = var.origin_ipv4
  proxied = true
  ttl     = 1 # 1 = automatic (required when proxied)
  comment = "DissQus app/API origin (nginx → relay). Managed by Terraform."
}

resource "cloudflare_record" "app_v6" {
  count   = var.origin_ipv6 == null ? 0 : 1
  zone_id = local.zone_id
  name    = var.app_host
  type    = "AAAA"
  value   = var.origin_ipv6
  proxied = true
  ttl     = 1
  comment = "DissQus app/API origin (IPv6). Managed by Terraform."
}

# --- Pre-prod origin (preprod.chat.<zone>) → the DEDICATED pre-prod VM --------
# Pre-prod runs on its own host now, not alongside prod on the production
# droplet, so this points at preprod_origin_ipv4 rather than origin_ipv4. Skipped
# entirely until that IP is supplied, so an apply from a half-configured
# environment can't publish a record aimed at the production origin.
resource "cloudflare_record" "preprod" {
  count   = (var.preprod_host == null || var.preprod_origin_ipv4 == null || var.preprod_origin_ipv4 == "") ? 0 : 1
  zone_id = local.zone_id
  name    = var.preprod_host
  type    = "A"
  value   = var.preprod_origin_ipv4
  proxied = true
  ttl     = 1
  comment = "DissQus pre-prod origin. Managed by Terraform."
}
