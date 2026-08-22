# One PoP per region: a VPC, a droplet running the full stack, and a firewall.
# `for_each` over var.pops so adding a region is a one-line change in tfvars.

resource "digitalocean_project" "dissqus" {
  name        = "dissqus-multiregion"
  description = "MQTT + PQ backend PoPs (broker/SFU/turn/keys) across regions."
  purpose     = "Web Application"
  environment = "Production"
  resources   = [for d in digitalocean_droplet.pop : d.urn]
}

# Regional private network (intra-region only — DO VPCs don't span regions;
# cross-region traffic uses the WireGuard mesh over public IPs).
resource "digitalocean_vpc" "pop" {
  for_each = var.pops
  name     = "dissqus-${each.key}"
  region   = each.value.do_region
}

resource "digitalocean_droplet" "pop" {
  for_each = var.pops

  name     = "dissqus-${each.key}"
  region   = each.value.do_region
  size     = var.droplet_size
  image    = var.droplet_image
  vpc_uuid = digitalocean_vpc.pop[each.key].id
  ssh_keys = var.ssh_key_fingerprints

  # Bootstrap: docker + compose, the WireGuard backbone, and the PoP stack.
  # Real key material / compose env is delivered out-of-band (see README), NOT
  # baked into user_data or state.
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    pop_name = each.key
    is_home  = try(each.value.is_home, false)
    wg_port  = var.wireguard_port
    all_pops = keys(var.pops)
  })

  tags = ["dissqus", "pop-${each.key}"]
}

# Per-PoP firewall (media lives on Cloudflare Realtime, so NO media/coturn ports):
#   443/tcp — HTTPS + MQTT-over-WSS, from Cloudflare IPs only
#   wg/udp  — backbone mesh (EMQX cluster-linking), only between our own droplets
#   22/tcp  — SSH, admin CIDR only
resource "digitalocean_firewall" "pop" {
  for_each    = var.pops
  name        = "dissqus-${each.key}"
  droplet_ids = [digitalocean_droplet.pop[each.key].id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = local.cloudflare_cidrs
  }

  # WireGuard backbone: only from the other droplets' public IPs.
  inbound_rule {
    protocol         = "udp"
    port_range       = tostring(var.wireguard_port)
    source_addresses = [for d in digitalocean_droplet.pop : "${d.ipv4_address}/32"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = [var.admin_cidr]
  }

  # Allow all egress.
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Optional managed Postgres in the home region (directory + social + offline
# queue metadata). Off by default — self-host on the home droplet to start.
resource "digitalocean_database_cluster" "pg" {
  count      = var.enable_managed_postgres ? 1 : 0
  name       = "dissqus-pg"
  engine     = "pg"
  version    = "16"
  size       = "db-s-1vcpu-1gb"
  region     = one([for k, v in var.pops : v.do_region if try(v.is_home, false)])
  node_count = 1
}
