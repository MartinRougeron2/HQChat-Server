# The production database: one DigitalOcean Managed Postgres cluster, reachable
# only from the production droplet.
#
# Production ONLY. Pre-prod runs a plain postgres container on its own droplet
# (infra/deploy/docker-compose.preprod.yml) — see README.md for why that is the
# separation rather than a second database on this cluster.
#
# This module deliberately does NOT create the droplet. It was created by hand
# (docs/runbooks/from-scratch.md §1) and is in no Terraform state, so it is read
# instead — which is also why this is its own module rather than a flag on
# infra/multiregion, where applying anything would first want to import a droplet
# it did not make.

data "digitalocean_droplet" "prod" {
  name = var.prod_droplet_name
}

resource "digitalocean_database_cluster" "hqcat" {
  name    = var.cluster_name
  engine  = "pg"
  version = var.pg_version
  size    = var.cluster_size
  region  = data.digitalocean_droplet.prod.region

  node_count = var.node_count

  # Join the droplet's VPC. This is what gives the cluster a `private_host` that
  # resolves inside the region and never leaves DigitalOcean's network.
  private_network_uuid = data.digitalocean_droplet.prod.vpc_uuid

  maintenance_window {
    day  = var.maintenance_window.day
    hour = var.maintenance_window.hour
  }
}

# --- Trusted sources --------------------------------------------------------
# DigitalOcean always publishes a PUBLIC hostname for a managed cluster; there is
# no switch to withdraw it. This firewall is therefore the closed door: with one
# droplet rule, every other source — the public internet, and every other droplet
# in the account including pre-prod — is refused before authentication. Combined
# with connecting over `private_host`, that is what "private" means here.
#
# Note this applies to BOTH endpoints. A trusted source is required even for a
# connection arriving over the VPC.
resource "digitalocean_database_firewall" "hqcat" {
  cluster_id = digitalocean_database_cluster.hqcat.id

  rule {
    type  = "droplet"
    value = data.digitalocean_droplet.prod.id
  }
}

resource "digitalocean_database_db" "prod" {
  cluster_id = digitalocean_database_cluster.hqcat.id
  name       = "hqcat_prod"
}

# --- Users ------------------------------------------------------------------
# Two roles, because they want very different things:
#   app_prod   — DML on every table; the services.
#   emqx_prod  — SELECT on mqtt_acl and nothing else; the broker's authorizer.
#
# DigitalOcean's API has no grant primitive, so the actual privileges are applied
# by the 000_roles.sql migration, which reads these names from APP_ROLE /
# EMQX_ROLE.
resource "digitalocean_database_user" "app_prod" {
  cluster_id = digitalocean_database_cluster.hqcat.id
  name       = "app_prod"
}

resource "digitalocean_database_user" "emqx_prod" {
  cluster_id = digitalocean_database_cluster.hqcat.id
  name       = "emqx_prod"
}

# --- Connection pool --------------------------------------------------------
# One, for the five Node services. Transaction mode is what makes a pool of this
# size serve all of them: a backend is held for the duration of a statement, not
# of a connection.
#
# EMQX is deliberately NOT behind it. A DigitalOcean pool binds to one database
# user, so the broker's read-only role would need a pool of its own — and behind
# a 15-minute authz cache it issues a handful of queries a minute, which is a
# rate transaction pooling multiplexes nothing out of. It connects direct
# instead: same backend cost, one less thing to operate, and
# `disable_prepared_statements` stops being load-bearing.
resource "digitalocean_database_connection_pool" "prod" {
  cluster_id = digitalocean_database_cluster.hqcat.id
  name       = "hqcat-prod-pool"
  mode       = "transaction"
  size       = var.pool_size
  db_name    = digitalocean_database_db.prod.name
  user       = digitalocean_database_user.app_prod.name
}

# The cluster's CA. Services connect with sslmode=verify-full, which needs it on
# disk — see the `pg_ca_cert` output and the runbook step that places it.
data "digitalocean_database_ca" "hqcat" {
  cluster_id = digitalocean_database_cluster.hqcat.id
}
