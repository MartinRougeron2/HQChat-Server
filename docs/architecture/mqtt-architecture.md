# DissQus — MQTT + PQ Microservices Architecture

Target architecture for splitting the current WS monolith
(the retired `/ws` monolith, deleted August 2026) into independently
scalable services. Supersedes the single-relay model for the messaging/call path;
the deployment/secrets model in [ARCHITECTURE.md](overview.md) still applies.

**Design axioms** (these drive every decision below):

1. **Split by trust, not just by feature.** Because the app is end-to-end
   encrypted, components fall into a *control plane* (touches identity, keys,
   money, social graph — request/response HTTP) and a *data plane* (sees only
   ciphertext — pure relays, optimized for latency and horizontal scale).
2. **HQC is the security root; classical crypto is trusted for nothing.** Every
   confidentiality guarantee rests on HQC-KEM-derived symmetric keys. TLS is an
   outer obfuscation wrapper only. Token signatures and call credentials are **PQ
   signatures or symmetric MACs**, never RSA/ECDSA.
3. **No P2P, ever.** All media is relayed (via **Cloudflare Realtime**'s SFU) so
   peers never learn each other's IP. "1:1" is just a 2-participant room.
4. **The control plane never touches a message or media byte.** It authenticates,
   directs, and mints credentials; the data plane moves the bytes.

---

## 1. Components — role + technology

### Control plane (stateful, security-critical, HTTP)

| Component | Role | Technology |
|---|---|---|
| **Keys / Identity service** | Runs the HQC-KEM auth handshake, owns the `pk ↔ username` directory + one-time prekey bundles, mints short-lived **PQ-signed tokens** (MQTT connect creds) and brokers **Cloudflare Realtime** session + TURN credentials for calls, enforces admission (paid app / open). The crown jewel. | Node/TS (reuse existing `services/server` code), HQC lib (native `.so` now → **WASM** per audit C1), Postgres for the directory and for challenge/nonce + admission state. PQ signatures: ML-DSA (Dilithium). |
| **Social service** | Friends, invites, social graph, block lists. Feeds the broker's dynamic ACL / friend-check. Can be folded into Keys for v1. | Node/TS, Postgres. |
| **Admission / billing** | Stripe webhooks, the email+OTP subscription claim, APNs key custody, entitlement state. Already exists as `services/{stripe,subscription,apns}`. | Node/TS, Stripe SDK, Resend. |
| **Push-bridge** | Subscribes `u/+/inbox`, checks presence, fires **content-free** APNs wakes for offline recipients. | Node/TS, MQTT client, APNs (existing `services/apns`). |
| **Blob API** | Issues signed upload/download URLs for E2E-encrypted attachments. Never sees plaintext or the blob key. | Node/TS + S3-compatible store (MinIO self-host / Cloudflare R2). |

### Data plane (ciphertext-only relays, latency-optimized)

| Component | Role | Technology |
|---|---|---|
| **MQTT broker** | The messaging backbone: message fanout, presence (LWT + retained), delivery receipts, offline queue (QoS 1 + persistent sessions), call **control** signaling. Enforces per-client topic ACLs from token claims. Sees ciphertext + metadata only. | **EMQX** (HTTP auth hook, PostgreSQL authorizer, MQTT 5, clustering). Session state in its own mnesia; the ACL in Postgres. |
| **Media / calls** | Always-relayed group calls (2 = a room of 2). Serverless, forward-only WebRTC **SFU + TURN** on Cloudflare's edge — global, cross-region over CF's backbone automatically, no droplets/ports to run. Reads RTP headers only — media stays E2E via **SFrame**. | **Cloudflare Realtime** (formerly Cloudflare Calls). |
| **Blob store** | Holds ciphertext attachment bytes. | S3-compatible object storage (Cloudflare R2). |

### Shared infra

| Component | Role | Technology |
|---|---|---|
| **Postgres** | Everything: directory, social graph, entitlements, the topic ACL, sessions, rate limits, challenges. Split into a durable tier and an `UNLOGGED` ephemeral tier — see [postgres-migration.md](postgres-migration.md). | DigitalOcean managed cluster ([`infra/database`](../../infra/database/README.md)); read replicas per region later. |
| **Edge** | TLS termination (**untrusted** wrapper), WAF, rate limiting, static site, geo-steering, origin firewalling, **and the Realtime SFU/TURN**. | Cloudflare. |

### Clients

Native iOS/macOS (Swift) speak **MQTT over raw TLS/TCP**; web speaks **MQTT over
WSS** (the broker's listener — not a bespoke WS server). Each device holds an HQC
identity keypair; `sk` never leaves the Secure Enclave-gated keychain. Call media
uses WebRTC against Cloudflare Realtime.

---

## 2. How components interact

```
            ┌──────────────────────── CONTROL PLANE (HTTP, PQ-signed) ─────────────────────┐
            │   Keys/Identity ── Social ── Admission/Billing ── Push-bridge ── Blob API     │
            │        │  Postgres          │ Stripe/StoreKit        │ APNs        │ signed URLs│
            └────────┼───────────────────────────────────────────┼─────────────┼───────────┘
   auth/token/creds  │ token verify (JWT hook)                     │ sub u/+/inbox│
   directory lookup  │ + dynamic ACL (friend check)                │              ▼
   Realtime creds ◀──┤                                             │        Blob store (R2)
                     ▼                                             │
  clients ──MQTT/TLS──▶┌──────────────┐   presence (LWT+retained)  │
  (native)             │ MQTT broker  │   messages / receipts ─────┘
  clients ──MQTT/WSS──▶│   (EMQX)     │   call CONTROL only (ring/accept/end)
  (web)                └──────┬───────┘
                              │  Postgres (sessions, ACL, rate limits)
        call MEDIA path       │
        (never on broker)     ▼
  clients ──WebRTC──▶ Cloudflare Realtime (SFU + TURN, global edge)
                      SFrame frames — CF forwards ciphertext, never decrypts
```

**Interaction rules**

- **Clients ↔ Keys** (HTTP): connect-time only — auth handshake, directory
  lookups, token minting, **Cloudflare Realtime session/TURN credential brokering**.
  Never in the per-message path.
- **Clients ↔ Broker** (MQTT): all messaging, presence, receipts, and call
  *control*. The broker calls the **Keys** service once to verify the connect
  token (JWT auth hook), and the **Social** service for dynamic publish ACLs
  (cached), so a device can only reach its friends' inboxes.
- **Clients ↔ Cloudflare Realtime** (WebRTC): all call *media*, always relayed.
  Each arrow is client→CF edge; peers are invisible to each other. Session gated
  by a short-lived credential the Keys service brokers.
- **Push-bridge ↔ Broker**: subscribes to inboxes, sends content-free APNs wakes
  when the recipient is offline.
- **Clients ↔ Blob**: encrypted-attachment upload/download via signed URLs; the
  decryption key travels *inside* the E2E message envelope, never to the store.

**Two encryption layers, both HQC-derived, TLS-independent**

- **Session layer** `ss_AS` (device↔server): authenticates the device, protects
  the connect token and control/metadata. From the connect-time KEM handshake.
- **Content layer**: feeds the KEM double ratchet ([e2ee-protocol.md](e2ee-protocol.md));
  encrypts all message content and derives call media keys. Neither the broker nor
  Cloudflare ever holds it.

---

## 3. Ideal flow (init → message → image → call)

**Register (once):** device generates `(pk, sk)`; `POST /register {username, pk}`
to Keys (admission-checked); directory stores `username → pk`.

**Connect / auth (PQ, TLS untrusted):**
1. `POST /auth/init {pk_A}` → Keys does `Encap(pk_A)→(ct, ss_AS)`, returns `ct`.
2. A does `Decap(sk_A, ct)→ss_AS` (proves possession of `sk_A`).
3. `POST /auth/verify {pk_A, HKDF(ss_AS,"auth")}` → Keys checks proof + admission,
   returns PQ-signed `T_A = {uid, deviceId, acl, exp}`.
4. `MQTT CONNECT (password=T_A)` → broker verifies the PQ signature, applies ACLs.
   Set **LWT** → `offline` on `u/uid_A/presence`; publish `online` (retained).

**Open the A↔B channel:** A looks up `pk_B`, `Encap(pk_B)→(ct_AB, ss_AB)`, inits
ratchet, publishes `{key_init, ct_AB}` to `u/uid_B/inbox`. Only `sk_B` recovers
`ss_AB`. Offline peers: A uses B's pre-published one-time prekey bundle instead.

**Text message A→B:** ratchet-encrypt → `PUBLISH u/uid_B/inbox` (QoS 1). Online →
delivered; offline → broker queues (persistent session) and Push-bridge sends an
APNs wake. B decrypts, publishes a receipt to `u/uid_A/receipts`.

**Image message A→B:** `K_img←random`; upload `Enc_K_img{bytes}` to Blob → `blobId`;
send an E2E envelope `{type:image, blobId, K_img}` over MQTT. B decrypts the
envelope, `GET` the blob, decrypts with `K_img`. The store only ever holds
ciphertext.

**Call A→B (always relayed via Cloudflare Realtime):**
1. A `GET /call-session` → Keys creates/joins a **Cloudflare Realtime** session and
   returns A's short-lived session + TURN credentials (`roomId` + CF creds).
2. A `PUBLISH u/uid_B/call  Enc{RING, roomId}` → B rings, `GET`s its own
   `/call-session` creds for the same `roomId`.
3. Both connect **WebRTC to Cloudflare Realtime** and push/pull tracks (client↔CF
   edge only — never to each other).
4. Media flows client→CF Realtime→client, **SFrame**-encrypted with
   `K_media = HKDF(ss_AB, "call"‖roomId)`. CF forwards frames per-receiver, reads
   headers only, and traverses regions on its own backbone. CF's TURN handles
   hostile/NAT'd networks (TCP/TLS 443).
5. `PUBLISH u/uid_B/call Enc{CALL_END}` tears down; clients leave the CF session.

Peers never exchange IPs; Cloudflare Realtime sees room membership + client IPs
(metadata, same trust level as the broker) but never media content.

---

## 4. Deploy & scale

Each tier scales on a different axis — the whole point of the split.

| Tier | State | Scaling axis | How |
|---|---|---|---|
| **Keys / Social / Admission / Blob API** | Stateless (state in Postgres) | Requests/sec at connect time | N replicas behind the LB; scale Postgres with read replicas. |
| **Push-bridge** | Stateless | Inbox message rate | Partition `u/+/inbox` subscriptions across replicas (shared MQTT subscriptions). |
| **MQTT broker (EMQX)** | Connection + session state (its own mnesia) | Concurrent connections | EMQX **cluster** — add nodes; sessions replicate across the cluster. Millions of connections per cluster. |
| **Media (Cloudflare Realtime)** | Managed by Cloudflare | Aggregate call bandwidth | **Nothing to run or scale** — serverless SFU/TURN on CF's edge, billed by usage. Removes the entire media droplet tier. |
| **Postgres** | The system of record | Read load / dataset | Writer + a streaming replica per region; the hot ephemeral tables never reach the writer at all. |

**Deployment path**

- **Today → phase 1:** Docker Compose (existing [docker-compose.yml](../../infra/deploy/docker-compose.yml))
  gains `keys`, `broker` (EMQX), `blob` services; keep the `*_FILE` secrets
  convention ([lib/config.ts](../../services/server/lib/config.ts)). Single VM.
- **Media tier:** **none to deploy** — provision a Cloudflare Realtime app + TURN
  key, store the App ID/secret as Keys-service secrets. CF handles regions and
  scale.
- **Scale-out:** move the stateless HTTP tier + EMQX to Kubernetes when a single VM
  saturates; each tier gets its own HPA. Postgres becomes managed or
  clustered. Cloudflare stays the edge (WAF, rate limiting, TLS wrapper, geo
  steering, Realtime media).
- **Regions:** Keys/Postgres central (or few); the Broker is regional (§6) so the
  messaging hot path stays close to users; media is already global via Cloudflare
  Realtime.

**Hardening carries over:** non-root, `cap_drop: ALL`, read-only rootfs,
`no-new-privileges`, pids/mem/cpu caps, rotated logs. The broker and blob store are
**ciphertext-only** — a compromise leaks metadata, never content; Cloudflare
Realtime is likewise ciphertext-only (SFrame).

---

## 5. Big implementation steps

Strangler pattern — the WS monolith keeps running until the last cutover. Order is
by dependency and risk.

0. **Extract the HTTP control plane.** Pull the existing `http` handlers
   (Stripe/StoreKit/subscribe/info) and the KEM auth logic out of `server.ts`
   into a standalone **Keys** service. No behavior change; moves billing secrets
   off the relay. *Enabler for everything else.*

1. **Make auth token-based.** Replace the in-connection WS challenge with the
   HTTP `/auth/init` + `/auth/verify` flow that returns a **PQ-signed token**.
   Introduce ML-DSA signing for tokens/creds (retire any classical signature).
   Add one-time prekey bundles to the directory for offline session init.

2. **Stand up EMQX; define topics + ACLs.** Wire the JWT auth hook (verify the
   token) and the dynamic-ACL hook (friend check via Social, cached). Lock down:
   subscribe only to own inbox/presence-of-friends; publish only to allowed
   inboxes. *This is the security boundary — get it right before cutover.*

3. **Cut messaging + presence to MQTT.** Move `DIRECT_MESSAGE`/`ROOM_MESSAGE`/
   receipts to inbox/receipt topics; replace the in-memory `onlineUsers` map with
   **LWT + retained** presence. Ship clients dual-homed (WS + MQTT) during the
   transition.

4. **Blob store for attachments.** Route `IMAGE_MESSAGE`/`AUDIO_MESSAGE` to the
   Blob API (ciphertext + signed URLs); the envelope carries `blobId + K_img`.
   Move streamed audio to the WebRTC data channel.

5. **Push-bridge.** Subscribe `u/+/inbox`, presence-check, content-free APNs. Retire
   the monolith's push path.

6. **Integrate Cloudflare Realtime for calls.** Split call **control** (MQTT
   `/call`) from **media** (client↔CF Realtime). Add a `/call-session` endpoint on
   Keys that brokers CF session + TURN creds; wire the client WebRTC to push/pull
   tracks against CF Realtime; enforce SFrame with the PQ-derived media key. No
   droplets, no coturn, no P2P path.

7. **Retire the WS monolith.** Once clients are MQTT-only and calls are on
   Cloudflare Realtime, delete `server.ts`'s relay/presence/call code. What remains
   of the old repo is the Keys/Admission service.

8. **Harden + regionalize.** PQ signatures everywhere, EMQX clustering + regional
   PoPs (§6), censorship-resistant transport (443, ECH, multi-region ingress), and
   the Cloudflare Durable Object exploration from [ARCHITECTURE.md](overview.md)
   once HQC→WASM (audit **C1**) lands.

**Milestone checkpoints:** after step 3 you can run **multiple broker/gateway
replicas** (the horizontal-scale unlock); after step 6 the server carries **zero
media** (it's on Cloudflare Realtime); after step 7 the monolith is gone and every
tier scales independently.

---

## 6. Multi-region & backbone

Users connect to their **nearest PoP**, and PoPs are stitched together by a
server-to-server **backbone** so cross-region traffic rides an optimized path
instead of the public internet. This applies to the **messaging** path only —
**call media is global out of the box** via Cloudflare Realtime, so there's no
media backbone to build.

**Target regions: London (`lon1`, home/writer), US-East (`nyc3`), Singapore
(`sgp1`).** **Starter = London only** — one droplet, everything co-located; add
NYC and Singapore by uncommenting two rows in the Terraform `pops` map. Once
Singapore is up, an AU/NZ user reaches it at ~90–100 ms instead of London at
~270 ms; US traffic lands on NYC instead of crossing the Atlantic.

### PoP composition

Each region runs a **broker PoP** — for a cheap start, co-located on one
DigitalOcean droplet via Docker Compose, split onto separate droplets per tier as
load grows:

- MQTT **broker** node (EMQX) — regional cluster.
- **keys/directory read-replica** so auth (the KEM handshake) runs locally with no
  cross-region round-trip on connect.

(No SFU/TURN on the droplet — media is Cloudflare Realtime.)

### Don't stretch one cluster across regions — link independent ones

One **independent** broker cluster per region, joined by **EMQX Cluster Linking**
(async subscription forwarding), *not* a single WAN-stretched cluster (consensus
over 200 ms links goes split-brain). A publish in Singapore forwards over the
backbone **only** to regions with a matching subscriber (e.g. London). Same rule
for Postgres (regional read-replicas, single writer in London) and the broker
(per-region, no cross-region consensus). With the London-only starter there is no
backbone yet — it lights up when the second PoP joins.

### Routing

- **Messages:** cluster-link subscription forwarding delivers to whichever PoP the
  recipient is attached to. Each user has a **home region** holding their offline
  queue; a small **async global session registry** (`uid → current PoP`) lets the
  home region forward to a roaming user's current PoP. Stale entries just cost one
  extra hop — eventual consistency is fine.
- **Calls:** no PoP routing — both clients connect to **Cloudflare Realtime**,
  which relays across its own global backbone. Each client's first hop lands on the
  nearest CF edge; the long-haul leg is CF's problem, not yours.

### The backbone (cheap + simple)

DigitalOcean has no cross-region private network, so the backbone is a
**WireGuard mesh between droplets** over the public internet, carrying **EMQX
Cluster Linking** traffic only. It's a **closed, mutually-authenticated trust
domain** (pinned keys), yet still carries **only E2E ciphertext for content** — a
backbone compromise leaks routing metadata, never messages. (Media never touches
this backbone; it's on Cloudflare Realtime.)

**Latency, honestly:** the win is the **first hop** (~170 ms saved for an AU/NZ
user once Singapore exists) and same-region messaging never leaving the region. The
long haul (Singapore↔London ~90 ms *one way*) is physics-bound — the backbone
smooths its jitter/loss, it doesn't beat the speed of light. Call media latency is
governed by Cloudflare's backbone independently.

---

## 7. Cloudflare — how it's used

Cloudflare is the **edge, the client-steering layer, and the media plane**;
DigitalOcean droplets are the messaging/keys origins. Per axiom 2, Cloudflare
terminates TLS but is **trusted for nothing** — the PQ + E2E layers sit underneath,
so CF (like the backbone) sees only ciphertext, including for call media (SFrame).

| Cloudflare feature | Used for |
|---|---|
| **DNS** | All records. HTTP/WSS endpoints **proxied** (orange-cloud) → DDoS + WAF + hidden origin IP. |
| **Load Balancing** (geo/latency steering) | Routes `chat.<zone>` to the **nearest healthy broker PoP**. One pool per PoP, health monitors on `/health`. |
| **Realtime** (SFU + TURN) | **All call media** — serverless, forward-only, global, E2E via SFrame. Replaces the LiveKit/coturn droplet tier entirely. |
| **Pages** | Hosts all static content (marketing/legal/download) off the droplets. |
| **WAF + Rate Limiting** | Edge abuse control on the keys/blob HTTP API and the MQTT-over-WSS endpoint, before traffic hits a droplet. |
| **TLS (Full strict) + ECH** | Untrusted outer wrapper; **Encrypted Client Hello** hides the SNI for the censorship story. |
| **Origin lock-down** | Droplets firewall 443 to **Cloudflare IP ranges only** (as [harden-vm.sh](../../infra/deploy/scripts/harden-vm.sh) already does). |
| **Argo Smart Routing** *(optional)* | Speeds the edge→droplet leg over CF's backbone while a DO origin exists; redundant once compute is CF-native. |

**Media on Cloudflare Realtime — how it fits the constraints:**

- **No P2P** — clients push/pull tracks to Cloudflare's edge, never to each other;
  peer IPs are never exposed (axiom 3). ✅
- **Always-relayed group model** — Realtime is an SFU; "1:1" is a 2-track room. ✅
- **E2E preserved** — clients encrypt frames with SFrame (`K_media` from the
  ratchet); CF forwards ciphertext and never decrypts.
- **Credentials** — the Keys service brokers short-lived CF session + TURN creds
  via `/call-session`, matching the "control plane mints call creds" model. The CF
  Realtime App ID/secret live as Keys-service secrets, never on the client.
- **No droplet media path** — WebRTC UDP goes straight to Cloudflare Realtime, so
  there are **no `sfu-<pop>` records, no open media ports, and no coturn** on the
  droplets. (This removes the old "media bypasses the CF proxy" workaround.)

**Remaining constraint for the messaging plane:** Cloudflare's cheap tier proxies
**HTTP/WebSocket only** (raw MQTT TCP would need Enterprise Spectrum), so **all
client control traffic is MQTT-over-WSS on 443** behind the CF proxy — which is why
the broker exposes a WSS listener even for native apps, keeping DDoS/WAF/geo-steering
on the cheap plan.

### From-zero infra: Cloudflare + DigitalOcean

The backend infra is rebuilt from scratch (app code untouched) with **Cloudflare +
DigitalOcean droplets** — cheapest and simplest that still gives geo-steering, a
messaging backbone, and global media. Terraform sketch lives in
[infra/multiregion/](../../infra/multiregion/) (this supersedes the single-origin
[infra/cloudflare/](../../infra/cloudflare/) module for the multi-region backend).

**Rough monthly cost:** *Starter (London only)* — one 2 GB/2 vCPU droplet,
everything co-located, Postgres self-hosted, no LB → **~$18/mo** + Cloudflare
Realtime usage (billed by call minutes/data, ~$0 at low volume). *Full 3-region* —
3 droplets ≈ $54 + Cloudflare Load Balancing ≈ $5 + managed Postgres ≈ $15 +
Realtime usage → **~$45–70/mo + media usage**. Moving media to Realtime also
**shrinks the droplets** (no SFU/coturn CPU or bandwidth), so they can stay small
longer.

### Static website operations — entirely on Cloudflare

Keep **all** static content off the droplets — the droplets serve only the dynamic
app (MQTT-over-WSS, keys/blob API). Everything a browser loads as a page or asset
is hosted and operated at Cloudflare's global edge:

- **Host on Cloudflare Pages.** The marketing/legal/download site builds and
  deploys to Pages, served from the edge worldwide with automatic TLS and preview
  deploys — **no origin, no droplet** in the path. (The existing `dissqus-home`
  Worker in [infra/cloudflare/workers.tf](../../infra/cloudflare/workers.tf) can stay
  as a thin overlay for the `/privacy` `/terms` `/support` legal routes; Pages
  covers the rest.)
- **Caching & delivery:** Cache Rules cache static assets at every colo; enable
  Tiered Cache, Brotli, and auto-minify. Static pages get near-zero TTFB globally
  and cost nothing in droplet bandwidth.
- **Routing/redirects:** apex ↔ `www`, and `/download` → the App Store, via
  **Redirect Rules** (no origin round-trip).
- **iOS deep-linking:** serve `/.well-known/apple-app-site-association` (universal
  links + associated domains) from Pages/Workers — static, edge-cached, versioned
  with the site.
- **DNS split:** apex/`www`/static are **proxied** records pointing at Pages;
  **only `chat.<zone>`** points at the droplets/LB. Marketing traffic and app
  traffic never share an origin.

Net: a marketing spike or a scraped landing page never touches — or bills — the
messaging infrastructure.

### Security — how it's managed & which rules are in place

Cloudflare is the **security front door**; per axiom 2 it is trusted for transport
hygiene only (PQ + E2E sit underneath, so the edge never sees plaintext). Its job
is **abuse/volume control and attack-surface reduction**, layered *in front of* the
server's own per-IP limiter and the broker's token/ACL checks.

**Shared-zone caveat first:** `example.com` also hosts other projects + email
([infra/cloudflare/variables.tf](../../infra/cloudflare/variables.tf) guardrails). So
**every rule below is host-scoped** (`http.host eq "chat.<zone>"`) and zone-wide
settings (SSL mode, HSTS) are left to the dashboard/per-hostname — *or* dedicate a
separate zone for the app. The Terraform lives in
[infra/multiregion/security.tf](../../infra/multiregion/security.tf), all cost-gated
off by default.

Layers, edge → origin:

1. **DDoS** — automatic L3/4 + L7, always on, all plans. No config.
2. **WAF custom rules** (all plans, host-scoped):
   - **Block scanner/secret probes** — `/wp-`, `/.env`, `/.git`, `/vendor/`.
   - **Block ops endpoints** — `/metrics`, `/admin` refused at the edge (the
     server already 404s `/metrics` without a token; this is belt-and-suspenders).
   - **HTTP method allowlist** — only `GET` (incl. the WS upgrade), `POST`,
     `HEAD`, `OPTIONS`; everything else blocked.
   - *(optional, off)* **Path allowlist** — positive-security model that blocks any
     path outside the known app surface (`/mqtt`, `/auth`, `/friends`,
     `/username`, `/users`, `/push`, `/account`, `/stripe`, `/donate`,
     `/supporters`, `/health`). Enable once routes are frozen.
3. **Rate limiting** (paid, host-scoped):
   - **`/auth/*` → 20/min/IP → managed challenge** — blunts KEM-handshake floods
     and credential stuffing (the sensitive surface).
   - **`POST /blob` → 60/min/IP → block** — caps upload abuse.
   - **API backstop → 300/min/IP → managed challenge**, explicitly **excluding
     `/mqtt`** (the long-lived MQTT-over-WSS connection must never be challenged)
     and `/health`.
4. **Managed rulesets** (Pro+): Cloudflare Managed Ruleset + OWASP Core Ruleset,
   scoped to the app host.
5. **Bot control:** Bot Fight Mode (Free) / Super Bot Fight Mode (Pro); **Turnstile**
   on the `/donate` page.
6. **Origin lock-down (two independent controls):**
   - Droplet firewall accepts `443` **only from Cloudflare IP ranges**
     ([pops.tf](../../infra/multiregion/pops.tf) + the pinned CIDR list).
   - **Authenticated Origin Pulls** — CF presents a client cert; the origin
     terminator requires it, so a *leaked droplet IP can't be hit directly* even on
     443. IP allowlist + mTLS together.
7. **TLS posture:** Full (strict) to origin, min TLS 1.2, **ECH** to hide the SNI
   (the censorship story), HSTS set per-hostname.

The `/mqtt` exclusion in (3) is the one rule you must never get wrong —
challenging the persistent connection would break every client. **Call media needs no WAF
rules** — it lives on Cloudflare Realtime, protected by short-lived, PQ-brokered
session/TURN credentials and SFrame E2E, entirely off the droplets.
