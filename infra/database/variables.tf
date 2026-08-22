variable "do_token" {
  description = "DigitalOcean API token. Leave null to use the DIGITALOCEAN_TOKEN env var (preferred)."
  type        = string
  default     = null
  sensitive   = true
}

# The droplet is created BY HAND (docs/runbooks/from-scratch.md §1) and is not in
# any Terraform state. This module only reads it, by name, to learn which VPC to
# join and which droplet id to trust. Pre-prod is not here at all — it runs its
# own postgres container.
variable "prod_droplet_name" {
  description = "Name of the production droplet, as it appears in the DO control panel."
  type        = string
  default     = "dissqus-prod"
}

variable "cluster_name" {
  description = "Name of the managed Postgres cluster."
  type        = string
  default     = "hqcat-pg"
}

variable "pg_version" {
  description = "Major PostgreSQL version. Bumping this in place is an in-place upgrade DigitalOcean performs during the maintenance window — change deliberately."
  type        = string
  default     = "17"
}

variable "cluster_size" {
  description = "Node size slug. db-s-1vcpu-1gb allows 22 backend connections, which is what the pool budget below is sized against."
  type        = string
  default     = "db-s-1vcpu-1gb"
}

# 1 = no standby: DigitalOcean's maintenance and any node failure are a full
# restart of the cluster, so production loses its database for minutes and every
# MQTT client is disconnected (EMQX denies when its authorizer cannot answer).
# 2 adds a standby and turns that into a ~10-30s failover, and moves the SLA from
# 99.5% to 99.95%. Raising this later is an in-place change — the cluster is NOT
# recreated — so starting at 1 costs nothing but the downtime it buys.
variable "node_count" {
  description = "Nodes in the cluster. 1 = no standby (cheapest); 2 = highly available."
  type        = number
  default     = 1
}

variable "maintenance_window" {
  description = "When DigitalOcean may restart the cluster to patch it. Pick the quietest hour: with node_count = 1 this IS an outage window."
  type = object({
    day  = string # lowercase day name, or "any"
    hour = string # "HH:MM:SS", UTC
  })
  default = {
    day  = "sunday"
    hour = "03:00:00"
  }
}

# --- Connection budget ------------------------------------------------------
# 22 backend connections on db-s-1vcpu-1gb, and production has all of them to
# itself. Five Node services go through one transaction-mode pool; EMQX connects
# direct with pool_size 2 (see main.tf for why it is not pooled).
#
#   pool 15 + EMQX 2 = 17, leaving 5 for migrations, `psql` and ops.
variable "pool_size" {
  description = "Backend connections reserved for the application pool."
  type        = number
  default     = 15
}
