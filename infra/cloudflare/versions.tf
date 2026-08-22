terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      # Pinned to v4 (mature, stable resource schemas used throughout this
      # module). v5 renamed/reshaped many resources (e.g. cloudflare_record →
      # cloudflare_dns_record, zone_settings_override → per-setting); migrating
      # is a separate, deliberate bump.
      version = "~> 4.52"
    }
  }

  # Remote state on Cloudflare R2 (S3-compatible). The non-secret settings
  # (bucket, key, endpoint, lock) live in backend.hcl; the R2 credentials come
  # from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the environment. Init with:
  #   terraform init -backend-config=backend.hcl
  # First-time migration from local state adds: -migrate-state
  backend "s3" {}
}
