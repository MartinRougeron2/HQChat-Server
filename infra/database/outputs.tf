# Everything here is written by hand onto the two hosts (see README.md). Nothing
# fetches it automatically: the deploy agent pulls an image, never a secret, and
# CI has no path to these boxes at all.

locals {
  # The direct endpoint, as the cluster admin. Migrations run here: DDL through a
  # transaction-mode pooler is a bad idea, and the pooler's user is deliberately
  # not allowed to create tables.
  direct_uri = format(
    "postgresql://%s:%s@%s:%d/%s?sslmode=verify-full",
    digitalocean_database_cluster.hqcat.user,
    digitalocean_database_cluster.hqcat.password,
    digitalocean_database_cluster.hqcat.private_host,
    digitalocean_database_cluster.hqcat.port,
    digitalocean_database_db.prod.name,
  )
}

output "private_host" {
  description = "VPC-internal hostname of the cluster. Resolves only from inside the region's VPC; this is the host every service should use."
  value       = digitalocean_database_cluster.hqcat.private_host
}

output "public_host" {
  description = "The public hostname DigitalOcean publishes and will not let you withdraw. Nothing should use it — it is here so you can confirm the trusted-sources firewall refuses it."
  value       = digitalocean_database_cluster.hqcat.host
}

# DigitalOcean hands out URIs with `sslmode=require`, which encrypts the
# connection but does not verify who is on the other end. Every consumer has the
# cluster CA on disk, so these upgrade to verify-full — the mode that also checks
# the hostname against the certificate.
output "database_url" {
  description = "DATABASE_URL for the prod services: the application pool, over the private endpoint."
  value       = replace(digitalocean_database_connection_pool.prod.private_uri, "sslmode=require", "sslmode=verify-full")
  sensitive   = true
}

output "database_url_direct" {
  description = "Migration/ops URI — cluster admin, direct endpoint, no pooler."
  value       = local.direct_uri
  sensitive   = true
}

# EMQX cannot take a URI: its authorizer wants server/database/username/password
# as separate fields (infra/deploy/emqx/emqx.conf), in ONE file of shell
# assignments because it reads the environment as configuration. The DIRECT
# endpoint, not the pool — see the pool comment in main.tf.
output "emqx_pg" {
  description = "EMQX authorizer credentials, shaped as the deploy/secrets/emqx_pg file."
  value = join("\n", [
    "AUTHZ_PG_SERVER=${digitalocean_database_cluster.hqcat.private_host}:${digitalocean_database_cluster.hqcat.port}",
    "AUTHZ_PG_DATABASE=${digitalocean_database_db.prod.name}",
    "AUTHZ_PG_USERNAME=${digitalocean_database_user.emqx_prod.name}",
    "AUTHZ_PG_PASSWORD=${digitalocean_database_user.emqx_prod.password}",
  ])
  sensitive = true
}

output "app_roles" {
  description = "Role names the 000_roles.sql migration grants to. Feed these to the migration runner as APP_ROLE / EMQX_ROLE."
  value = {
    app  = digitalocean_database_user.app_prod.name
    emqx = digitalocean_database_user.emqx_prod.name
  }
}

output "pg_ca_cert" {
  description = "The cluster CA, PEM. Placed on each host as the pg_ca_cert secret so services can use sslmode=verify-full."
  value       = data.digitalocean_database_ca.hqcat.certificate
  sensitive   = true
}
