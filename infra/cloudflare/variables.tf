variable "cloudflare_api_token" {
  description = "Cloudflare API token. Leave null to use the CLOUDFLARE_API_TOKEN env var (preferred)."
  type        = string
  default     = null
  sensitive   = true
}

variable "account_id" {
  description = "Cloudflare account id (Workers + notifications are account-scoped)."
  type        = string
}

variable "zone_name" {
  description = "The Cloudflare zone (apex domain)."
  type        = string
  # Deliberately no default. `example.com` was one, and when release.yml did not
  # pass a value the plan came out as `chat.example.com` ->
  # `chat.example.com`: a plan that, applied, would have retargeted every record
  # in the module at a domain nobody owns. An unset zone must fail, not default.
}

variable "origin_ipv4" {
  description = "Public IPv4 of the VM running the relay (the nginx origin)."
  type        = string
}

variable "origin_ipv6" {
  description = "Public IPv6 of the VM, or null to skip the AAAA records."
  type        = string
  default     = null
}

variable "app_host" {
  description = "Subdomain (relative to the zone) for the production app/API origin."
  type        = string
  default     = "chat"
}

variable "preprod_origin_ipv4" {
  description = <<-EOT
    Public IPv4 of the SEPARATE pre-prod VM. Pre-prod used to share the
    production droplet (isolated only by compose project name and remapped host
    ports), so this record pointed at var.origin_ipv4. It now has its own host.
    Leave null/"" to skip the record entirely.
  EOT
  type        = string
  default     = null
}

variable "preprod_host" {
  description = "Subdomain for the pre-prod origin, or null to skip it."
  type        = string
  default     = "preprod.chat"
}

variable "manage_worker" {
  description = "Manage the dissqus-home Worker script + its legal-page routes."
  type        = bool
  default     = true
}

variable "worker_route_host" {
  description = "Host the legal pages are served on (overlays whatever already answers this host — e.g. the Vercel apex)."
  type        = string
  # No default, for the same reason as zone_name: a Worker route silently bound
  # to example.com is a route that does nothing, on a zone that is not yours.
}

variable "worker_legal_paths" {
  description = "Exact paths routed to the Worker. Intentionally NOT '/' so a shared apex (Vercel) keeps serving its homepage."
  type        = list(string)
  default     = ["/privacy", "/terms", "/support"]
}

# SHARED ZONE GUARDRAILS — example.com also hosts Vercel/backend/bbia/yt +
# Cloudflare Email. The following are ZONE-WIDE and would affect those too, so
# they default OFF. Turn on only if you accept the blast radius (or dedicate a zone).
variable "manage_zone_settings" {
  description = "[ZONE-WIDE] Manage SSL mode/HSTS/TLS/etc. Affects ALL projects on the zone. Default off on a shared zone."
  type        = bool
  default     = false
}

variable "manage_security_rules" {
  description = "[ZONE-WIDE] Manage the WAF custom-rules entrypoint. Terraform REPLACES it — import existing rules first. Default off."
  type        = bool
  default     = false
}

variable "worker_name" {
  description = "Name of the marketing/legal Worker script (matches apps/web/wrangler.toml so TF adopts the existing one)."
  type        = string
  default     = "dissqus-home"
}

variable "worker_compatibility_date" {
  type    = string
  default = "2025-01-01" # matches apps/web/wrangler.toml
}

# --- PRO-plan features ------------------------------------------------------
# Written and ready, but DEFAULT OFF so a Free-plan `apply` succeeds. Flip these
# to true (here or in terraform.tfvars) once the zone is on Pro.
variable "enable_rate_limiting" {
  description = "[PRO] Edge rate-limiting ruleset. WAF rate-limiting rules require a paid plan — leave false on Free."
  type        = bool
  default     = false
}

variable "enable_health_check" {
  description = "[PRO] Standalone Health Check on origin /health + email alert. Enable on Pro."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Email to notify when the origin health check fails."
  type        = string
  default     = ""
}

variable "hsts_max_age" {
  description = "Strict-Transport-Security max-age (seconds). 0 disables the managed HSTS header."
  type        = number
  default     = 31536000
}
