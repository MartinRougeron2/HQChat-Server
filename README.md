# hqchat server

The server half of [hqchat](https://github.com/MartinRougeron2/HQCAT), an
end-to-end encrypted messenger with a post-quantum handshake.

It is not a relay in the usual sense: **it never sees a message.** It proves that
a client holds a private key, decides who may publish to which topic, and lets
EMQX fan out ciphertext it has no key for. The interesting code is all in the
first two of those.

Licensed **AGPL-3.0** ([LICENSE](./LICENSE)).

## Services

One image, several entrypoints. All of them run on one VM today.

| Service | Entrypoint | Owns |
|---|---|---|
| **auth** | `auth/main.ts` | the HQC-KEM handshake, session + MQTT tokens, admission, and the EMQX authn hook |
| **app-api** | `api/main.ts` | directory, friend graph (which writes the broker's topic ACL), push tokens, account deletion, payments |
| **push-bridge** | `push/main.ts` | subscribes to every conversation, sends a content-free APNs wake to offline members |
| **broker-watch** | `ops/broker-watch.ts` | polls EMQX and Redis health, escalates transitions to Sentry |
| **helper bot** | `bot/bot.ts` | the account every new user starts with — an ordinary MQTT client, no special privileges |

Plus **EMQX** (messaging, per-topic ACL, offline sessions) and **Redis** (tokens,
ACL, friend graph, directory), neither of which is in this repo.

`legacy/` is the retired single-WebSocket monolith. It does not run; it is kept
for its end-to-end tests. See [legacy/README.md](legacy/README.md).

## Running it

```bash
npm ci
npm run typecheck && npm test

# the whole stack, including EMQX and Redis
docker compose -f ../../infra/deploy/docker-compose.yml up -d
```

Individual services: `npm run auth`, `npm run api`, `npm run push`,
`npm run bot`, `npm run broker-watch`. Each needs Redis; `auth` and the bot also
need the native HQC library (see below).

Configuration is environment variables — see `infra/deploy/.env.example`. There
are no defaults pointing at anyone's deployment: unset means unset, and the
services say so at startup.

## The native HQC library

`lib/hqc.ts` dlopens a native shared library built from the HQC reference
implementation (`lib/libhqc_x86.so`, linux/x86_64, glibc — which is why the
Docker image is Debian-based and not Alpine). The wrapper's source lives in the
monorepo under `native/hqc/`.

## How it fits together

- [Authentication](https://github.com/MartinRougeron2/HQCAT/blob/main/docs/architecture/auth-flow.md) — the handshake, and why there are two tokens
- [Messaging](https://github.com/MartinRougeron2/HQCAT/blob/main/docs/architecture/message-flow.md) — one message end to end, and what each hop can see
- [The topic ACL](https://github.com/MartinRougeron2/HQCAT/blob/main/docs/architecture/emqx-acl.md) — the only thing between a stranger and a conversation
- [Audits](https://github.com/MartinRougeron2/HQCAT/tree/main/docs/audits) — including the open findings

## Where this code lives

This repository is a mirror. The server is developed in the
[HQCAT monorepo](https://github.com/MartinRougeron2/HQCAT) alongside the Apple
clients and the infrastructure, and published here as a `git subtree` from
`services/server/`.

Issues and pull requests are welcome here. A PR against this repo is pulled back
into the monorepo with `git subtree pull`, so nothing is lost — but if you are
changing something that touches the clients too, the monorepo is the easier place
to do it.

## Security

Please report vulnerabilities privately — see
[SECURITY.md](https://github.com/MartinRougeron2/HQCAT/blob/main/SECURITY.md).
Known open findings are listed in the audits linked above; check there first.
