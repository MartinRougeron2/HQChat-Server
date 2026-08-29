# The marketing + legal site Worker (apps/site). Deployed straight from source —
# it's a single ESM module with no build step — so Terraform is the single
# source of truth for the code AND its routes. (`wrangler dev` still works for
# local iteration; don't `wrangler deploy` to prod — see apps/site/wrangler.toml.)
#
# NOTE on var.worker_name: it is the Cloudflare script identifier, and changing
# it FORCES REPLACEMENT — Terraform destroys the script and recreates it, and
# the routes move with it. The gap is seconds, but two of those routes are the
# privacy and support URLs registered with App Store Connect, so rename it
# deliberately (e.g. once the hqchat/DissQus naming question is settled), not as
# a drive-by tidy.
resource "cloudflare_workers_script" "site" {
  count      = var.manage_worker ? 1 : 0
  account_id = var.account_id
  name       = var.worker_name
  content    = file("${path.module}/../../apps/site/src/index.js")
  module     = true # ESM (export default { fetch })

  compatibility_date = var.worker_compatibility_date
}

# Routes: each path is an EXACT Worker route overlaying whatever already answers
# that host. `var.worker_route_host` is the app host (hqchat.<zone>), which also
# serves the API — so the list must never contain "/*". A glob there would
# swallow /auth, /mqtt, /subscribe, /stripe/webhook and /health and take the
# product down. "/" on its own matches the root path only, which is what puts
# the marketing site at the root without touching any API path.
resource "cloudflare_workers_route" "legal" {
  for_each    = var.manage_worker ? toset(var.worker_paths) : toset([])
  zone_id     = local.zone_id
  pattern     = "${var.worker_route_host}${each.value}"
  script_name = cloudflare_workers_script.site[0].name
}

# ── Future migration (stateless endpoints → the edge) ────────────────────────
# `/health`, `/mqtt`, `/stripe/webhook` and `/subscribe` stay on
# the ORIGIN. Other stateless endpoints can move to a Worker by adding routes
# like the one below (and the matching handler in the Worker). Keep /health off
# the Worker so the health check (health.tf) measures the real origin.
#
# resource "cloudflare_workers_route" "info" {
#   zone_id     = local.zone_id
#   pattern     = "${local.app_fqdn}/info"
#   script_name = cloudflare_workers_script.site[0].name
# }
