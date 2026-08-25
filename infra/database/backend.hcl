# Remote state on Cloudflare R2 (S3-compatible), same pattern as
# infra/cloudflare/backend.hcl. R2 credentials come from AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY in the environment. Init with:
#   terraform init -backend-config=backend.hcl
bucket = "your-tfstate-bucket"
key    = "database/terraform.tfstate"

# `endpoints.s3`, not `endpoint`: the bare parameter is deprecated and warns on
# every init. infra/cloudflare/backend.hcl already uses the current form.
#
# The account id is committed rather than left as a placeholder. It was
# REPLACE_ME, patched by `sed -i` inside the From scratch workflow at run time,
# which meant the file in the repo could not init anywhere else -- a local
# `terraform init` for step 3 of the bootstrap failed on a hostname that does
# not resolve. The same id is already committed in infra/cloudflare/backend.hcl,
# and infra/mirror/scrub.py rewrites it for the public mirror.
endpoints                   = { s3 = "https://<your-cloudflare-account-id>.r2.cloudflarestorage.com" }
region                      = "auto"
skip_credentials_validation = true
skip_region_validation      = true
skip_metadata_api_check     = true
skip_requesting_account_id  = true
use_path_style              = true
