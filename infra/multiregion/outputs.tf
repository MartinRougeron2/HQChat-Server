output "pop_public_ips" {
  description = "PoP name → droplet public IPv4. The deploy step feeds these into each droplet's WireGuard peer config to build the backbone mesh."
  value       = { for k, d in digitalocean_droplet.pop : k => d.ipv4_address }
}

output "pop_private_ips" {
  description = "PoP name → VPC private IPv4 (intra-region only)."
  value       = { for k, d in digitalocean_droplet.pop : k => d.ipv4_address_private }
}

output "app_endpoint" {
  description = "Hostname clients connect to (geo-steered when the LB is enabled)."
  value       = "${var.app_host}.${var.zone_name}"
}

output "media" {
  description = "Call media runs on Cloudflare Realtime (SFU + TURN), not the droplets. Provision a Realtime app + TURN key in the Cloudflare dashboard/API and store the App ID/secret as Keys-service secrets."
  value       = "cloudflare-realtime"
}

output "postgres_uri" {
  description = "Managed Postgres connection URI (only when enable_managed_postgres)."
  value       = var.enable_managed_postgres ? digitalocean_database_cluster.pg[0].uri : "self-hosted on home droplet"
  sensitive   = true
}
