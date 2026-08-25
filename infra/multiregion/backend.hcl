# Remote state on Cloudflare R2 (S3-compatible), same pattern as
# infra/cloudflare/backend.hcl. R2 credentials come from AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY in the environment. Init with:
#   terraform init -backend-config=backend.hcl
bucket = "your-tfstate-bucket"
key    = "multiregion/terraform.tfstate"

# `endpoints.s3`, not the deprecated bare `endpoint`; account id committed
# rather than a placeholder, for the same reasons as infra/database/backend.hcl.
endpoints                   = { s3 = "https://<your-cloudflare-account-id>.r2.cloudflarestorage.com" }
region                      = "auto"
skip_credentials_validation = true
skip_region_validation      = true
skip_metadata_api_check     = true
skip_requesting_account_id  = true
use_path_style              = true
