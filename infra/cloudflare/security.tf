# Edge rate limiting — the first line in front of the relay, complementing the
# server's per-IP limiter (audit H5) and nginx's 20 r/s. Throttles the HTTP API
# per IP but EXCLUDES the long-lived WebSocket upgrade (/mqtt) and the health
# probe (/health) so neither is ever challenged.
#
# The exclusion used to name `/ws`, the monolith socket retired at Phase 4. That
# path stopped existing and `/mqtt` took its place, which meant the live
# WebSocket upgrade was inside the rule — and its action is `managed_challenge`,
# which an MQTT-over-WebSocket client cannot solve. Any client sharing an IP
# (CGNAT, an office, a campus) that crossed the threshold would simply stop
# being able to connect, with no error a user could act on.
resource "cloudflare_ruleset" "rate_limit" {
  count       = var.enable_rate_limiting ? 1 : 0
  zone_id     = local.zone_id
  name        = "dissqus-rate-limit"
  description = "Per-IP API rate limiting (managed by Terraform)."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    ref         = "api_per_ip"
    description = "Throttle API requests per IP (exclude /mqtt and /health)."
    expression  = "(http.host eq \"${local.app_fqdn}\" and not (starts_with(http.request.uri.path, \"/mqtt\") or http.request.uri.path eq \"/health\"))"
    action      = "managed_challenge"
    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 100
      mitigation_timeout  = 60
    }
  }
}

# WAF custom rules — available on all plans (Free gets up to 5). Drops obvious
# scanners hammering the origin host.
#
# ⚠️ ZONE-WIDE entrypoint: a cloudflare_ruleset for http_request_firewall_custom
# REPLACES the zone's entire custom-rules entrypoint. If you already have custom
# rules in the dashboard (for other projects), import them into this resource
# first or you'll lose them. Off by default (var.manage_security_rules). The rule
# itself is scoped to the chat host, so it only acts on DissQus traffic.
resource "cloudflare_ruleset" "waf_custom" {
  count       = var.manage_security_rules ? 1 : 0
  zone_id     = local.zone_id
  name        = "dissqus-waf-custom"
  description = "Custom WAF rules (managed by Terraform)."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    ref         = "block_scanners"
    description = "Block common scanner/secret-probe paths on the app host."
    expression  = "(http.host eq \"${local.app_fqdn}\" and (http.request.uri.path contains \"/wp-\" or http.request.uri.path contains \"/.env\" or http.request.uri.path contains \"/.git\" or http.request.uri.path contains \"/vendor/\"))"
    action      = "block"
  }
}
