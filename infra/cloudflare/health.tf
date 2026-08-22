# Standalone Health Check against the ORIGIN /health (kept on the VM on purpose,
# so this measures the real relay, not the edge). Cloudflare probes from multiple
# regions and records latency/uptime vitals you can see in the dashboard
# (Traffic → Health Checks) and alert on.
resource "cloudflare_healthcheck" "origin" {
  count   = var.enable_health_check ? 1 : 0
  zone_id = local.zone_id
  name    = "dissqus-origin-health"
  address = local.app_fqdn

  type             = "HTTPS"
  port             = 443
  method           = "GET"
  path             = "/health"
  expected_codes   = ["200"]
  expected_body    = "ok"
  follow_redirects = false
  allow_insecure   = false

  interval              = 60 # seconds between probes
  timeout               = 5
  retries               = 2
  consecutive_fails     = 2 # mark unhealthy after N fails
  consecutive_successes = 2

  description = "Origin relay liveness + latency vitals. Managed by Terraform."
}

# Email alert when the origin health check changes state.
resource "cloudflare_notification_policy" "origin_health" {
  count       = var.enable_health_check && var.alert_email != "" ? 1 : 0
  account_id  = var.account_id
  name        = "dissqus-origin-health-alert"
  description = "Notify on origin health check failures. Managed by Terraform."
  enabled     = true
  alert_type  = "health_check_status_notification"

  email_integration {
    id = var.alert_email
  }

  filters {
    health_check_id = [cloudflare_healthcheck.origin[0].id]
    status          = ["Unhealthy", "Healthy"]
  }
}
