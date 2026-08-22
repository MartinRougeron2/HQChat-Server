variable "do_token" {
  description = "DigitalOcean API token. Leave null to use the DIGITALOCEAN_TOKEN env var (preferred)."
  type        = string
  default     = null
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token. Leave null to use the CLOUDFLARE_API_TOKEN env var (preferred)."
  type        = string
  default     = null
  sensitive   = true
}

variable "zone_name" {
  description = "Cloudflare zone (apex domain)."
  type        = string
  default     = "example.com"
}

variable "app_host" {
  description = "Subdomain (relative to the zone) clients connect to. Fronted by the CF load balancer and geo-steered to the nearest PoP."
  type        = string
  default     = "chat"
}

variable "ssh_key_fingerprints" {
  description = "Fingerprints of SSH keys already registered in DigitalOcean, injected into every droplet."
  type        = list(string)
}

variable "admin_cidr" {
  description = "CIDR allowed to SSH to the droplets (your admin IP/range). Everything else is denied."
  type        = string
}

# The set of PoPs. Keys are logical names; `do_region` is the DO slug (syd1,
# lon1, nyc3, fra1, sgp1, ...). Start with 2–3 and add rows to grow.
variable "pops" {
  description = "Regional PoPs to deploy. One droplet each (all services co-located) for the cheap MVP."
  type = map(object({
    do_region = string                # DigitalOcean region slug
    is_home   = optional(bool, false) # the home region holds the Postgres writer + primary offline queue
  }))
  # STARTER: London only. Target topology is lon + nyc + sgp — uncomment the
  # other two rows to grow (DigitalOcean has no "eastus" slug; its US-East DC is
  # NYC, so US-East => nyc3).
  default = {
    lon = { do_region = "lon1", is_home = true } # London — Europe + home/writer
    # nyc = { do_region = "nyc3" }                # US East (DO's East-US DC is NYC)
    # sgp = { do_region = "sgp1" }                # Singapore — serves APAC/AU/NZ
  }
}

variable "droplet_size" {
  description = "Droplet size slug. s-2vcpu-2gb (~$18/mo) comfortably co-locates broker+SFU+turn+keys for an MVP."
  type        = string
  default     = "s-2vcpu-2gb"
}

variable "droplet_image" {
  description = "Base image slug."
  type        = string
  default     = "ubuntu-24-04-x64"
}

# Call media is served by Cloudflare Realtime (SFU + TURN on CF's edge), so the
# droplets expose NO media ports — no media_port_range needed.

variable "wireguard_port" {
  description = "UDP port for the server-to-server WireGuard backbone mesh."
  type        = number
  default     = 51820
}

# --- Cost-gated toggles (default OFF so a first apply is minimal/cheap) ------
variable "enable_load_balancer" {
  description = "Create the Cloudflare Load Balancer + pools + monitor for geo-steering (paid add-on ~$5/mo). Off = plain per-PoP DNS only."
  type        = bool
  default     = false
}

variable "enable_managed_postgres" {
  description = "Provision a DO Managed Postgres in the home region (adds ~$15/mo). Off = self-host Postgres on the home droplet."
  type        = bool
  default     = false
}

# --- Security (see security.tf) ---------------------------------------------
variable "manage_security_rules" {
  description = "Manage the zone's WAF custom-rules entrypoint. ⚠️ A cloudflare_ruleset for this phase REPLACES the whole entrypoint — import existing dashboard rules first on a shared zone. Rules here are host-scoped to the app so they only act on app traffic."
  type        = bool
  default     = false
}

variable "enable_rate_limiting" {
  description = "[PRO] Edge rate-limiting ruleset for the app host. Advanced rate-limiting needs a paid plan — leave false on Free."
  type        = bool
  default     = false
}

variable "enable_managed_waf" {
  description = "[PRO] Deploy Cloudflare's Managed Ruleset + OWASP Core Ruleset on the app host. Paid plans only."
  type        = bool
  default     = false
}

variable "enable_authenticated_origin_pulls" {
  description = "Require Cloudflare's client cert on origin TLS (mTLS CF→origin) so a leaked origin IP can't be hit directly even on 443. Needs the CF cert installed at the origin terminator too."
  type        = bool
  default     = false
}
