# Cloudflare R2 backend (non-secret settings). Committed on purpose.
# Credentials are NOT here — set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from
# an R2 API token before `terraform init -backend-config=backend.hcl`.
#
# One-time bootstrap (see README "Remote state"): enable R2, create the bucket
# `your-tfstate-bucket`, create an R2 API token, then migrate local → R2 with:
#   terraform init -backend-config=backend.hcl -migrate-state

bucket    = "your-tfstate-bucket"
key       = "cloudflare/terraform.tfstate"
region    = "auto"
endpoints = { s3 = "https://<your-cloudflare-account-id>.r2.cloudflarestorage.com" }

# Native S3 state locking (Terraform >= 1.10) — no DynamoDB needed, works on R2.
use_lockfile = true

# R2 isn't AWS — skip the AWS-specific preflight checks.
skip_credentials_validation = true
skip_metadata_api_check     = true
skip_region_validation      = true
skip_requesting_account_id  = true
skip_s3_checksum            = true
use_path_style              = true
