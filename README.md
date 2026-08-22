# hqchat server

The server half of **hqchat**, an end-to-end encrypted messenger with a
post-quantum handshake — and, since it is no use reading a server you cannot
run, everything needed to deploy it: compose files, Terraform, NixOS hosts and
the runbooks that put them in order.

It is not a relay in the usual sense: **it never sees a message.** It proves a
client holds a private key, decides who may publish to which topic, and lets
EMQX fan out ciphertext it has no key for.

Licensed **AGPL-3.0** ([LICENSE](LICENSE)).

## What is here

| Path | What lives there |
|---|---|
| [`services/server/`](services/server/) | the services themselves — auth · app-api · push-bridge · broker-watch · helper bot |
| [`infra/deploy/`](infra/deploy/) | compose, nginx, EMQX config, the pull agent, operational scripts |
| [`infra/nixos/`](infra/nixos/) | the hosts — a flake, one file per machine, nothing configured by hand |
| [`infra/cloudflare/`](infra/cloudflare/), [`infra/database/`](infra/database/), [`infra/multiregion/`](infra/multiregion/) | Terraform: the edge, the managed Postgres, the regional PoPs |
| [`.github/workflows/`](.github/workflows/) | CI, release, promote — and `from-scratch`, which builds an environment from nothing |
| [`docs/architecture/`](docs/architecture/) | how it fits together, and what each hop can see |
| [`docs/runbooks/`](docs/runbooks/) | standing one up, deploying to it, debugging it |

The paths are the ones the monorepo uses, so a link inside any file here means
the same thing there.

**Not here:** the macOS and iOS clients, and the security audits. The clients are
closed for now; the audits track findings that are still open, and publishing a
list of unfixed weaknesses alongside the code that has them is a favour to the
wrong reader. What the audits conclude is summarised in
[SECURITY.md](SECURITY.md).

## Running it locally

Needs Node 22 and Docker.

```bash
cd services/server && npm ci
npm run typecheck && npm test
```

The unit suite skips its database-backed tests when there is nothing to connect
to, so that passes on a bare checkout.

The whole stack, against a throwaway Postgres container:

```bash
sh infra/deploy/local-secrets/generate.sh    # once — writes local credentials
docker compose -f infra/deploy/docker-compose.yml \
               -f infra/deploy/docker-compose.local.yml up -d
```

## Deploying it for real

Read [`docs/runbooks/from-scratch.md`](docs/runbooks/from-scratch.md) first —
it is the whole path, DigitalOcean through Cloudflare to a serving host, in the
order the dependencies actually run. Most of it is automated by the
[From scratch workflow](.github/workflows/from-scratch.yml): everything a cloud
API can do it does, idempotently, and it hands back a rendered script for the
steps that need SSH.

What you supply is a domain on Cloudflare, a DigitalOcean account, and an APNs
key if you want push. The workflows are here because you need them — `release`
builds and publishes the image, `promote` moves the production channel, `host`
builds the NixOS closures — but they are configured for a deployment that is not
yours, and Actions is switched off on this repository for that reason. Fork it,
set your secrets (`infra/deploy/scripts/set-ci-secrets.sh` writes the whole set),
then turn Actions on in your copy. What the design assumes, and what you should not quietly
undo:

- **Hosts pull, CI never connects.** Nothing in GitHub can reach a server. The
  host agent notices a new image digest and applies it; a leaked CI token buys
  an attacker a registry push, not a shell.
- **The origin is not reachable except through Cloudflare.** The firewall names
  Cloudflare's ranges, and the origin address is worth as much as a password.
- **Postgres holds tokens, the topic ACL and the friend graph — never
  plaintext.** The per-topic ACL is the only barrier between a stranger and a
  conversation, and topic names are derivable from two public keys.

Every value that names a deployment is a placeholder here: `example.com`,
`YOUR-GITHUB-ACCOUNT`, `<your-origin-ipv4>`. Grep for them — the list of things
you must set is exactly the list of placeholders you find.

## How it fits together

- [Authentication](docs/architecture/auth-flow.md) — the handshake, and why there are two tokens
- [Messaging](docs/architecture/message-flow.md) — one message end to end, and what each hop can see
- [The topic ACL](docs/architecture/emqx-acl.md) — the only thing between a stranger and a conversation
- [Deployment architecture](docs/architecture/overview.md) — how code and secrets reach a host
- [Components and regions](docs/architecture/components-regions.md) — what can be moved closer to users

## Where this code lives

This repository is generated. The server and the infrastructure are developed in
a private monorepo alongside the Apple clients, and published here by
`infra/mirror/publish.sh`, which copies the paths above and rewrites every value
that names the reference deployment.

Issues and pull requests are welcome — a PR here is applied to the monorepo by
hand and comes back on the next sync, so nothing is lost, but the commit you see
land will not be the one you wrote.

## Security

Report vulnerabilities privately: open a
[security advisory](https://github.com/MartinRougeron2/HQChat-Server/security/advisories/new)
on this repository rather than a public issue. See [SECURITY.md](SECURITY.md).
