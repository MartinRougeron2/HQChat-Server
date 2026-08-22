# Cloudflare Realtime (formerly Cloudflare Calls) — the call MEDIA plane.
#
# There is intentionally NO Terraform resource here: the cloudflare v4 provider
# has no stable Calls/Realtime resource, so the Realtime app + TURN key are
# provisioned via the Cloudflare API (or dashboard) and their credentials handed
# to the Keys service as secrets. Media never touches the droplets.
#
# Provision once (App = SFU, TURN key = relay creds):
#
#   # SFU app
#   curl -sX POST \
#     "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/calls/apps" \
#     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
#     -d '{"name":"dissqus-realtime"}'
#   # -> returns { uid (APP_ID), secret (APP_SECRET) }
#
#   # TURN key
#   curl -sX POST \
#     "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/calls/turn_keys" \
#     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
#     -d '{"name":"dissqus-turn"}'
#   # -> returns { uid (TURN_KEY_ID), secret (TURN_KEY_API_TOKEN) }
#
# Store the four values as Keys-service secrets (same *_FILE convention as
# server/messages/lib/config.ts):
#   CF_REALTIME_APP_ID / CF_REALTIME_APP_SECRET
#   CF_TURN_KEY_ID     / CF_TURN_KEY_API_TOKEN
#
# The Keys service then, per call:
#   - creates/joins a Realtime session with APP_ID/APP_SECRET,
#   - mints a short-lived TURN credential from the TURN key,
#   - returns both to the client at GET /call-session (see ARCHITECTURE_MQTT.md §3).
#
# Requires the CF API token to also carry the "Calls:Edit" (account) scope.
