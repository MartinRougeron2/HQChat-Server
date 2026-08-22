# Cloudflare edge: geo-steered app hostname (proxied HTTP/WSS) + direct media
# records (unproxied, since CF's cheap tier can't proxy WebRTC UDP).

locals {
  zone_id  = data.cloudflare_zone.this.id
  app_fqdn = "${var.app_host}.${var.zone_name}"

  # Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips/).
  # Pin here so origin firewalls only accept edge traffic; refresh when CF
  # updates them (same maintenance as harden-vm.sh).
  cloudflare_cidrs = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  ]
}

# --- Direct (unproxied) per-PoP records --------------------------------------
# origin-<pop>: the droplet, used as the load-balancer pool origin + WSS target.
resource "cloudflare_record" "origin" {
  for_each = var.pops
  zone_id  = local.zone_id
  name     = "origin-${each.key}"
  type     = "A"
  content  = digitalocean_droplet.pop[each.key].ipv4_address
  proxied  = false # LB pools reference origins directly; media needs the raw IP
  ttl      = 300
}

# NOTE: no sfu-<pop> media records — call media is served by Cloudflare Realtime
# (SFU + TURN on CF's edge), not by the droplets. Clients reach Realtime directly;
# the Keys service brokers short-lived CF session/TURN credentials.

# --- App hostname: geo-steered load balancer (proxied) -----------------------
# When enable_load_balancer=false, fall back to a single proxied A record on the
# home PoP so a first apply works on the Free plan without the LB add-on.
resource "cloudflare_record" "app_fallback" {
  count   = var.enable_load_balancer ? 0 : 1
  zone_id = local.zone_id
  name    = var.app_host
  type    = "A"
  content = digitalocean_droplet.pop[one([for k, v in var.pops : k if try(v.is_home, false)])].ipv4_address
  proxied = true # DDoS + WAF + hidden origin
  ttl     = 1
}

resource "cloudflare_load_balancer_monitor" "health" {
  count          = var.enable_load_balancer ? 1 : 0
  type           = "https"
  port           = 443
  method         = "GET"
  path           = "/health"
  interval       = 60
  retries        = 2
  timeout        = 5
  expected_codes = "200"
  description    = "dissqus PoP origin health"
}

# One pool per PoP so the LB can steer to the nearest healthy region.
resource "cloudflare_load_balancer_pool" "pop" {
  for_each = var.enable_load_balancer ? var.pops : {}
  name     = "dissqus-${each.key}"
  monitor  = cloudflare_load_balancer_monitor.health[0].id

  origins {
    name    = "origin-${each.key}"
    address = digitalocean_droplet.pop[each.key].ipv4_address
    enabled = true
  }
}

resource "cloudflare_load_balancer" "app" {
  count            = var.enable_load_balancer ? 1 : 0
  zone_id          = local.zone_id
  name             = "${var.app_host}.${var.zone_name}"
  default_pool_ids = [for k in keys(var.pops) : cloudflare_load_balancer_pool.pop[k].id]
  fallback_pool_id = cloudflare_load_balancer_pool.pop[one([for k, v in var.pops : k if try(v.is_home, false)])].id
  proxied          = true
  steering_policy  = "dynamic_latency" # route each client to the lowest-RTT healthy PoP

  # WSS + long-lived MQTT connections: keep sticky so a client stays on one PoP.
  session_affinity     = "cookie"
  session_affinity_ttl = 1800
}
