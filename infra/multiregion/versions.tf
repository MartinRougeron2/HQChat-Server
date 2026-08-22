terraform {
  required_version = ">= 1.5.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
    cloudflare = {
      # Pinned to v4 to match infra/cloudflare (v5 reshaped resource schemas).
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
  }

  # Remote state on Cloudflare R2 (S3-compatible), same pattern as
  # infra/cloudflare. Non-secret settings live in backend.hcl; R2 creds come from
  # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the environment. Init with:
  #   terraform init -backend-config=backend.hcl
  backend "s3" {}
}
