# The provider reads the API token from DIGITALOCEAN_TOKEN when `token` is null,
# so the secret is never written to a tfvars file or a state input.
#
# Token scope: a scoped token with read+write on Databases (and read on
# Droplets, for the two data sources below).

provider "digitalocean" {
  token = var.do_token # null => falls back to DIGITALOCEAN_TOKEN
}
