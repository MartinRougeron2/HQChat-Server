# `local-secrets/`

The four database secrets the base compose stack requires, pointing at the
throwaway `postgres` container in
[`docker-compose.local.yml`](../docker-compose.local.yml).

```bash
sh infra/deploy/local-secrets/generate.sh
```

The values are **not** secret — they authenticate to a container that exists only
on a laptop or a CI runner, and they match the `POSTGRES_*` env in the overlay.
They are generated rather than committed for one reason: a committed connection
URI trips every secret scanner that looks at this repo, and a security gate that
is permanently red is a security gate nobody reads. The generated files are
gitignored.

Production credentials never come near this directory. They live in
`/etc/hqcat/<stack>/secrets/` on the host, placed from `terraform output` in
[`infra/database`](../../database/README.md), and the base compose file resolves
`./secrets/*` — not `./local-secrets/*` — for them.

`pg_ca_cert` is written empty on purpose: the local container speaks plain
postgres, so there is no certificate to verify. `services/db/pg.ts` falls back to
an unencrypted connection when the CA file is empty or unreadable, and
`lib/config.ts` only insists on `sslmode=verify-full` when `NODE_ENV=production`.
