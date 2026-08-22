# The marketing/legal site Worker (apps/web). Deployed straight from source —
# it's a single ESM module with no build step — so Terraform is the single
# source of truth for the code AND its routes. (`wrangler dev` still works for
# local iteration; don't `wrangler deploy` to prod — see apps/web/wrangler.toml.)
resource "cloudflare_workers_script" "site" {
  count      = var.manage_worker ? 1 : 0
  account_id = var.account_id
  name       = var.worker_name
  content    = file("${path.module}/../../apps/web/src/index.js")
  module     = true # ESM (export default { fetch })

  compatibility_date = var.worker_compatibility_date
}

# Routes: ONLY the legal pages, on the shared apex. We deliberately do NOT route
# "/" or "/*", so the Vercel apex keeps serving everything else. Each path is an
# exact Worker route that overlays the apex origin just for that URL.
resource "cloudflare_workers_route" "legal" {
  for_each    = var.manage_worker ? toset(var.worker_legal_paths) : toset([])
  zone_id     = local.zone_id
  pattern     = "${var.worker_route_host}${each.value}"
  script_name = cloudflare_workers_script.site[0].name
}

# ── Future migration (stateless endpoints → the edge) ────────────────────────
# `/health`, `/ws`, `/stripe/webhook` and `/subscribe` stay on
# the ORIGIN. Other stateless endpoints can move to a Worker by adding routes
# like the one below (and the matching handler in the Worker). Keep /health off
# the Worker so the health check (health.tf) measures the real origin.
#
# resource "cloudflare_workers_route" "info" {
#   zone_id     = local.zone_id
#   pattern     = "${local.app_fqdn}/info"
#   script_name = cloudflare_workers_script.site[0].name
# }
