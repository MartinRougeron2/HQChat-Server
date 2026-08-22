output "zone_id" {
  description = "Resolved Cloudflare zone id."
  value       = local.zone_id
}

output "app_fqdn" {
  description = "Production app/API hostname (origin)."
  value       = local.app_fqdn
}

output "preprod_fqdn" {
  description = "Pre-prod hostname, or null when no pre-prod record is managed."
  # Read off the resource, not the local: the record is skipped when
  # preprod_origin_ipv4 is unset, and the output should say so rather than name
  # a hostname that resolves to nothing.
  value = one(cloudflare_record.preprod[*].hostname)
}

output "worker_routes" {
  description = "Exact URLs the dissqus-home Worker serves (legal pages)."
  value       = [for r in cloudflare_workers_route.legal : r.pattern]
}

output "health_check_id" {
  description = "Standalone health check id (empty if disabled)."
  value       = var.enable_health_check ? cloudflare_healthcheck.origin[0].id : ""
}
