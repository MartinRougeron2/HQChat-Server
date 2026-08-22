# Zone-wide TLS + security posture. Mirrors what deploy/nginx.conf and the
# security audit assume: Full (strict) origin TLS, HTTPS forced, modern TLS,
# HSTS, and WebSockets enabled (required for /ws).
#
# ⚠️ ZONE-WIDE: example.com also serves Vercel/backend/bbia. SSL=strict
# requires EVERY proxied origin on the zone to present a valid cert — enabling
# this can break another project that relies on Full (non-strict). Off by default
# (var.manage_zone_settings). Only turn on once you've confirmed every origin has
# a valid cert, or after dedicating a zone to DissQus.
resource "cloudflare_zone_settings_override" "this" {
  count   = var.manage_zone_settings ? 1 : 0
  zone_id = local.zone_id

  settings {
    ssl                      = "strict" # Full (strict): validate the origin cert. NEVER "flexible".
    always_use_https         = "on"     # 80 → 443 at the edge.
    automatic_https_rewrites = "on"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    opportunistic_encryption = "on"
    websockets               = "on" # /ws relies on this.
    brotli                   = "on"
    http3                    = "on"
    zero_rtt                 = "off" # avoid 0-RTT replay surface on the API.
    security_level           = "medium"
    browser_check            = "on"
    # Managed HSTS at the edge (in addition to nginx's header).
    security_header {
      enabled            = var.hsts_max_age > 0
      max_age            = var.hsts_max_age
      include_subdomains = true
      preload            = true
      nosniff            = true
    }
  }
}
