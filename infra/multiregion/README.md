# infra/multiregion — Cloudflare + DigitalOcean backend (sketch)

From-zero, multi-region backend for the MQTT + PQ architecture
(../../deploy/ARCHITECTURE_MQTT.md, §6–7).
App code is untouched — this is **infrastructure only**.

> **Status: sketch.** The resource shapes, variables, and wiring are real, but
> two pieces are intentionally stubbed to out-of-band deploy steps: **WireGuard
> key/peer material** and the **PoP compose stack + secrets**. Neither belongs in
> Terraform state. Treat this as the skeleton to iterate on, not a clean
> `apply`-and-done.

## What it creates

- One **DigitalOcean droplet per PoP** (`var.pops`), all services co-located for
  the cheap MVP (**EMQX broker + keys read-replica** — no media services).
- A per-region **VPC** and a **firewall** (443 from Cloudflare only, WireGuard only
  between our droplets, SSH from `admin_cidr` — **no media/coturn ports**).
- **Cloudflare**: unproxied `origin-<pop>` records; and — when
  `enable_load_balancer=true` — a **geo-steered Load Balancer** (`dynamic_latency`)
  that routes clients to the nearest healthy PoP. Off by default → a single
  proxied A record on the home PoP, so a first apply works on the Free plan.
- Optional **DO Managed Postgres** in the home region (`enable_managed_postgres`).

**Call media = Cloudflare Realtime** (SFU + TURN on CF's edge), provisioned via
the API — see [realtime.tf](realtime.tf). No droplets, ports, or coturn for media;
the Keys service brokers short-lived CF session/TURN creds at `/call-session`.

## The backbone

DO has no cross-region private network, so PoPs mesh over **WireGuard on public
IPs**. Terraform outputs `pop_public_ips`; the deploy step generates a keypair
per droplet, writes `/etc/wireguard/wg0.conf` with each peer's pubkey + endpoint,
and `wg-quick up`. **EMQX Cluster Linking** rides the tunnels (messaging only —
call media is on Cloudflare Realtime and never crosses this backbone).

## Cloudflare, specifically

- **Proxied** app hostname → DDoS + WAF + hidden origin; clients speak
  **MQTT-over-WSS on 443** through it (CF's cheap tier proxies HTTP/WS, not raw
  MQTT TCP — which is why the broker exposes a WSS listener).
- **Load Balancer** with `dynamic_latency` steering = "connect to nearest server".
- **Media = Cloudflare Realtime** (SFU + TURN on CF's edge) — clients reach it
  directly, off the droplets. No `sfu-<pop>` records, no media ports. Media is
  SFrame ciphertext; CF forwards, never decrypts. See [realtime.tf](realtime.tf).
- Origin firewall pins **Cloudflare IP ranges** (in `cloudflare.tf` `locals`;
  refresh when CF updates them).

## Usage

```bash
cd infra/multiregion
cp terraform.tfvars.example terraform.tfvars   # fill in fingerprints, admin_cidr, pops
export DIGITALOCEAN_TOKEN=...                   # DO API token
export CLOUDFLARE_API_TOKEN=...                 # scoped: DNS:Edit, Load Balancing:Edit, Zone:Read, Calls:Edit
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...   # R2 state creds
# edit backend.hcl (R2 endpoint), then:
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

## Regions

Target set is **London (`lon1`, home) + US-East (`nyc3`) + Singapore (`sgp1`)**.
**Starter ships London only** — add the other two by uncommenting their rows in
the `pops` map. DO has no `eastus` slug; its US-East DC is NYC (`nyc3`).

## Cost

| Item | ~ / mo |
|---|---|
| **Starter — 1 × `s-2vcpu-2gb` (London), LB+PG off, self-hosted PG** | **~$18** |
| Full — 3 × `s-2vcpu-2gb` droplets | $54 |
| Cloudflare Load Balancing (when enabled) | $5 |
| Managed Postgres (when enabled; else free on home droplet) | $15 |

Scale a tier onto its own droplet only when it saturates.

## Static site & security

- **Static content** (marketing/legal/download, `apple-app-site-association`) is
  hosted entirely on **Cloudflare Pages** — off the droplets. Only `chat.<zone>`
  points at the droplets/LB. See `deploy/ARCHITECTURE_MQTT.md` §7.
- **Security rules** live in [security.tf](security.tf), all **host-scoped** to the
  app FQDN (safe on the shared zone) and cost-gated off by default: WAF custom
  rules (scanner/ops-endpoint/method blocks), rate limits (`/auth`, `/blob`, API
  backstop — excluding `/ws`), optional managed/OWASP rulesets, and Authenticated
  Origin Pulls. Toggle via `manage_security_rules`, `enable_rate_limiting`,
  `enable_managed_waf`, `enable_authenticated_origin_pulls`.

## Not covered here (deliberately)

- WireGuard keys/peers and the PoP compose stack + secrets → out-of-band deploy
  step (mirror the `*_FILE` secrets pattern in
  ../../server/messages/lib/config.ts).
- EMQX cluster-linking config → app config, not infra.
- Cloudflare Realtime app/TURN-key provisioning → API step in [realtime.tf](realtime.tf);
  the resulting App ID/secret + TURN key become Keys-service secrets.
- The single-origin [../cloudflare](../cloudflare) module is superseded by this
  for the multi-region backend; keep it only if you still front the legacy relay.
