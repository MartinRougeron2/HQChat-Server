# DissQus Server

The open-source server component for **DissQus**, a privacy-first, post-quantum
secure messenger. It is a thin **relay**: it routes messages by username and
queues offline delivery, but it never holds the keys needed to read message
content or call media — those are end-to-end encrypted between clients (AES-256-GCM
under a per-friend key exchanged via HQC). Control-plane frames (the action type,
routing metadata) are additionally encrypted hop-by-hop with a per-connection,
per-direction key derived from a dedicated HQC key exchange.

Licensed under **AGPL-3.0** (see [LICENSE](./LICENSE)). The DissQus client apps are
separate and not covered by this license.

## Topology

Each server is its own **island**: a profile talks only to users on the same
server (no federation yet). Run your own server and it's a self-contained network.

## Requirements

- Node.js 20+
- Redis
- The **HQC native library** (`lib/libhqc_x86.so`, Linux/x86). HQC is a
  post-quantum KEM; its source and build are external to this repo — build the
  shared library from the HQC reference implementation and place it at
  `lib/libhqc_x86.so`. (Tip: do this inside a Docker image so self-hosters never
  touch the native toolchain.)

## Configure

Copy `deploy/.env.example` to `.env` and fill it in. Key settings:

- `ADMISSION_POLICY` — `open` (default), `allowlist`, or `stripe`.
  - `open`: anyone who passes HQC auth. Best for self-hosting.
  - `allowlist`: only public keys in `ADMISSION_ALLOWLIST`.
  - `stripe`: requires an active Stripe subscription (the official server).
- `EXEMPT_PUBLIC_KEYS` — always bypass admission (e.g. the helper bot).
- `SERVER_NAME`, `PUBLIC_BASE_URL` — advertised at `GET /info`.
- `REDIS_URL`, `PORT`. Stripe/APNs only as needed.

## Run

```sh
npm ci
npm run typecheck && npm test
npx tsx server.ts          # or via PM2: deploy/ecosystem.config.js
```

## Endpoints

- `GET /health` — liveness.
- `GET /info` — `{ name, version, protocolVersion, admission, features }`. Clients
  probe this to validate a URL and learn whether a subscription is required.
- `WS /ws` — the app protocol.
- `POST /stripe/webhook`, `/subscribe*` — only used with `ADMISSION_POLICY=stripe`.
