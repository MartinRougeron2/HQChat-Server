# Cloudflare security for the app host. EVERY rule is scoped to local.app_fqdn
# (http.host eq "<app>") so it is safe on the SHARED zone (example.com also
# hosts Vercel/backend/email). Zone-wide settings (SSL mode, HSTS) are NOT managed
# here for the same reason — set those per-hostname in the dashboard, or dedicate a
# zone for the app.
#
# Defense in depth: these edge rules sit in FRONT of the server's own per-IP
# limiter and the broker's token/ACL checks. The app is PQ + E2E, so the edge
# never sees plaintext — its job is abuse/volume control and shrinking attack
# surface, not confidentiality.

# --- 1. WAF custom rules (all plans; Free allows up to 5) --------------------
# ⚠️ This resource REPLACES the zone's custom-rules entrypoint. Import existing
# dashboard rules first on a shared zone. Off by default (manage_security_rules).
resource "cloudflare_ruleset" "waf_custom" {
  count       = var.manage_security_rules ? 1 : 0
  zone_id     = local.zone_id
  name        = "dissqus-waf-custom"
  description = "Host-scoped custom WAF rules (managed by Terraform)."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # Block scanners / secret-probe paths.
  rules {
    ref         = "block_scanners"
    description = "Block common scanner/secret-probe paths on the app host."
    expression  = "(http.host eq \"${local.app_fqdn}\" and (http.request.uri.path contains \"/wp-\" or http.request.uri.path contains \"/.env\" or http.request.uri.path contains \"/.git\" or http.request.uri.path contains \"/vendor/\"))"
    action      = "block"
  }

  # Never expose ops endpoints at the edge (server already 404s /metrics without a
  # token — this is belt-and-suspenders).
  rules {
    ref         = "block_ops_endpoints"
    description = "Block /metrics and /admin from the internet."
    expression  = "(http.host eq \"${local.app_fqdn}\" and (starts_with(http.request.uri.path, \"/metrics\") or starts_with(http.request.uri.path, \"/admin\")))"
    action      = "block"
  }

  # Method allowlist: the app only needs GET (incl. the WS upgrade), POST, HEAD,
  # OPTIONS. Block the rest to cut surface.
  rules {
    ref         = "method_allowlist"
    description = "Block HTTP methods the app never uses."
    expression  = "(http.host eq \"${local.app_fqdn}\" and not http.request.method in {\"GET\" \"POST\" \"HEAD\" \"OPTIONS\"})"
    action      = "block"
  }

  # OPTIONAL positive-security model: allow only known path prefixes, block the
  # rest. Brittle (must track every route) — commented until routes are frozen.
  # rules {
  #   ref         = "path_allowlist"
  #   description = "Block any path outside the known app surface."
  #   expression  = "(http.host eq \"${local.app_fqdn}\" and not (starts_with(http.request.uri.path, \"/ws\") or starts_with(http.request.uri.path, \"/auth\") or starts_with(http.request.uri.path, \"/blob\") or starts_with(http.request.uri.path, \"/stripe\") or starts_with(http.request.uri.path, \"/claim\") or http.request.uri.path in {\"/health\" \"/info\" \"/subscribe\"}))"
  #   action      = "block"
  # }
}

# --- 2. Rate limiting (paid plan for advanced rules) -------------------------
resource "cloudflare_ruleset" "rate_limit" {
  count       = var.enable_rate_limiting ? 1 : 0
  zone_id     = local.zone_id
  name        = "dissqus-rate-limit"
  description = "Per-IP rate limits for the app host (managed by Terraform)."
  kind        = "zone"
  phase       = "http_ratelimit"

  # Auth is the sensitive surface: throttle the KEM handshake to blunt credential
  # stuffing / handshake floods. Never touches /ws (the long-lived MQTT-over-WSS
  # connection) or /health.
  rules {
    ref         = "auth_per_ip"
    description = "Throttle POST /auth/* per IP."
    expression  = "(http.host eq \"${local.app_fqdn}\" and starts_with(http.request.uri.path, \"/auth\"))"
    action      = "managed_challenge"
    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 20
      mitigation_timeout  = 300
    }
  }

  # Blunt blob-upload abuse.
  rules {
    ref         = "blob_per_ip"
    description = "Throttle blob writes per IP."
    expression  = "(http.host eq \"${local.app_fqdn}\" and http.request.method eq \"POST\" and starts_with(http.request.uri.path, \"/blob\"))"
    action      = "block"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 60
      mitigation_timeout  = 60
    }
  }

  # General API backstop, excluding the WSS upgrade + health probe.
  rules {
    ref         = "api_per_ip"
    description = "Backstop per-IP throttle (exclude /ws and /health)."
    expression  = "(http.host eq \"${local.app_fqdn}\" and not http.request.uri.path in {\"/ws\" \"/health\"})"
    action      = "managed_challenge"
    ratelimit {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 60
      requests_per_period = 300
      mitigation_timeout  = 60
    }
  }
}

# --- 3. Managed rulesets (Pro+): Cloudflare Managed + OWASP -------------------
resource "cloudflare_ruleset" "waf_managed" {
  count       = var.enable_managed_waf ? 1 : 0
  zone_id     = local.zone_id
  name        = "dissqus-waf-managed"
  description = "Deploy CF Managed + OWASP rulesets, scoped to the app host."
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    ref         = "cf_managed"
    description = "Cloudflare Managed Ruleset on the app host."
    expression  = "(http.host eq \"${local.app_fqdn}\")"
    action      = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee" # Cloudflare Managed Ruleset
    }
  }
  rules {
    ref         = "owasp"
    description = "OWASP Core Ruleset on the app host."
    expression  = "(http.host eq \"${local.app_fqdn}\")"
    action      = "execute"
    action_parameters {
      id = "4814384a9e5d4991b9815dcfc25d2f1f" # OWASP Core Ruleset
    }
  }
}

# --- 4. Authenticated Origin Pulls (mTLS CF -> origin) -----------------------
# Closes the gap where someone finds the droplet IP and hits 443 directly: the
# origin (nginx / EMQX WSS terminator) is configured to require CF's client cert,
# so only Cloudflare can complete the TLS handshake. Complements the IP allowlist
# in the droplet firewall. Requires installing CF's cert on the origin too.
resource "cloudflare_authenticated_origin_pulls" "app" {
  count   = var.enable_authenticated_origin_pulls ? 1 : 0
  zone_id = local.zone_id
  enabled = true
}
