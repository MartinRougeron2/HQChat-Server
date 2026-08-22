terraform {
  required_version = ">= 1.5.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
  }

  # Remote state on Cloudflare R2 (S3-compatible), same pattern as
  # infra/cloudflare and infra/multiregion. Non-secret settings live in
  # backend.hcl; R2 credentials come from AWS_ACCESS_KEY_ID /
  # AWS_SECRET_ACCESS_KEY in the environment. Init with:
  #   terraform init -backend-config=backend.hcl
  backend "s3" {}
}
