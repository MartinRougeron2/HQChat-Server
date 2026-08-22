# Host configuration (NixOS)

The machines that run the DissQus stack, declared. This replaces
`infra/deploy/scripts/harden-vm.sh` and `infra/deploy/agent/install-agent.sh` —
~200 lines of imperative shell that was *applied once* and then free to drift —
with a definition that is **enforced on every rebuild**.

> **Status: not yet evaluated.** These files have never been through `nix flake
> check` (no Nix on the machine they were written on, and no CI minutes to spare).
> Treat the first `nix flake check` as part of the review, not a formality.
> Nothing here is live until a host is actually installed.

## Why NixOS and not cloud-init or a golden image

Immutable-image approaches get determinism by making you replace the machine,
which turns every host change into a state migration — Docker volumes, EMQX's
mnesia, `/etc/hqcat`. `nixos-rebuild switch` is an **in-place atomic transition**:
the new generation activates, state is untouched, and the previous generation
stays bootable for rollback. Same determinism, no migration.

## Shape

The host follows a channel pointer in the R2 binary cache, the same way the app
follows a GHCR channel tag:

```
  app  : GHCR :prod tag        → image digest → docker compose up   (2 min poll)
  host : R2 /channels/prod     → store path   → switch-to-configuration (30 min)
```

CI evaluates and builds; hosts only substitute. **A host never fetches the
flake, never evaluates Nix, and never builds** (`max-jobs = 0` makes that a hard
failure rather than an hour of compiling on a 2 GB droplet). So there is still
no source code on any server.

Trust comes from signatures, not from the bucket: Nix refuses a store path that
is not signed by a key in `trusted-public-keys`, so a writable cache is not
enough to compromise a host — you would need the signing key, which exists only
as a GitHub secret.

**NixOS owns the host; the agent still owns the app.** Shipping the app is
Promote, as before, and does not touch host config.

| File | What |
|---|---|
| `flake.nix` | the two hosts; `nix build .#toplevel-prod` |
| `hosts/*.nix` | the only facts that differ: stack + domain |
| `modules/hardening.nix` | sshd, fail2ban, sysctls (`harden-vm.sh` §2–5) |
| `modules/firewall.nix` | nftables; 80/443 Cloudflare-only (§1) |
| `modules/docker.nix` | daemon settings (§6) |
| `modules/nginx.nix` | the vhost, translated from `infra/deploy/nginx.conf` |
| `modules/app-agent.nix` | the app agent as a unit (`install-agent.sh`) |
| `modules/host-agent.nix` | pulls + activates published closures |
| `modules/cloudflare-ips.nix` | pinned edge ranges — generated, do not hand-edit |
| `install-origin-cert.sh` | puts the Origin cert on a host (run from your laptop) |

## One-time setup

**1. Signing key.** The public half is committed; the private half never leaves
GitHub.

```bash
nix key generate-secret --key-name hqcat-cache-1 > cache-key.sec
nix key convert-secret-to-public < cache-key.sec        # → hqcat-cache-1:AAAA…
gh secret set NIX_CACHE_SIGNING_KEY --env production < cache-key.sec
rm cache-key.sec
```

Put the public key in `modules/options.nix` (`cachePublicKey`). Evaluation fails
while it is still the placeholder — deliberately.

**2. The cache bucket.** A second R2 bucket, public-read, fronted by Cloudflare
so hosts fetch over HTTPS from `cache.<zone>`:

```bash
gh variable set NIX_CACHE_BUCKET --env production --body 'dissqus-nix-cache'
gh variable set R2_ENDPOINT      --env production --body 'https://<account>.r2.cloudflarestorage.com'
gh secret   set R2_CACHE_SECRET_ACCESS_KEY --env production   # write token for that bucket
```

**3. Install NixOS onto the droplet.** DigitalOcean has no NixOS image;
`nixos-anywhere` kexecs an installer onto the existing box and converts it in
place. Destructive to the OS — take a snapshot first.

```bash
nix run github:nix-community/nixos-anywhere -- \
  --flake .#prod root@<droplet-ip>
```

**4. Machine state that is deliberately NOT in the closure.** The Nix store is
world-readable, so no private key can live in it. These go on the host directly.

*The Cloudflare Origin certificate.* Get it from the dashboard → your zone →
SSL/TLS → Origin Server → Create Certificate (the private key is shown once):

```bash
./install-origin-cert.sh root@<ip> ~/origin.pem ~/origin.key
```

That validates the pair locally before touching the host — wrong file type,
empty file, or a cert and key that do not match are all rejected on your laptop
rather than after nginx is already serving a broken pair. It then installs with
the right owner/mode, runs `nginx -t`, and reloads only if the config is valid.

**The host does not wait for this to boot.** Until the real certificate is
installed, `hqcat-origin-cert.service` generates a self-signed placeholder so
nginx starts and the rest of the stack comes up. Cloudflare Full (strict)
answers **526** in that state — that is the symptom to recognise. A missing
certificate must not be able to fail activation, because
`hqcat-host-agent` would read a failed activation as a bad release and try to
roll back a host that has no earlier generation.

*App secrets.* Written straight to the host; nothing is echoed and nothing is
left in `/tmp`:

```bash
for s in stripe_secret_key stripe_webhook_secret resend_api_key apns_key_p8; do
  read -rsp "$s (blank to skip): " v; echo
  [ -n "$v" ] && printf '%s' "$v" \
    | ssh root@<ip> "umask 077; cat > /etc/hqcat/prod/secrets/$s"
done
```

You do not have to supply all of them. NixOS creates every compose secret as an
empty file (`f` tmpfiles rules never truncate a real one), so an unused
Stripe/APNs key does not stop the stack — and `hqcat-otp-pepper.service`
generates the OTP pepper on the host, since that one must never be empty and
has no external source.

*GHCR pull credentials* (read-only `read:packages`; skip if the package is
public):

```bash
printf 'GHCR_USER=…\nGHCR_TOKEN=…\n' \
  | ssh root@<ip> 'umask 077; cat > /etc/hqcat/agent-auth.env'
```

*Non-secret config:*

```bash
ssh root@<ip> 'umask 077; cat > /etc/hqcat/prod/server.env' <<'ENV'
SERVER_NAME=DissQus
PUBLIC_BASE_URL=https://chat.example.com
ADMISSION_POLICY=stripe
ENV
```

## Day to day

Change a module, open a PR — CI proves it evaluates and builds. Merge to `main`
— CI signs, publishes, and moves the pointer. Hosts switch within 30 minutes.

```bash
systemctl start hqcat-host-agent.service    # don't wait for the timer
journalctl -u hqcat-host-agent.service -f
nix-env -p /nix/var/nix/profiles/system --list-generations
nixos-rebuild switch --rollback             # break glass, on the box
```

Roll back centrally by putting an older store path back in
`s3://<bucket>/channels/prod` — the closure is still cached and still signed.

## Known rough edges

- **Cloudflare ranges are pinned** in `modules/cloudflare-ips.nix` so a host
  boots closed without depending on `cloudflare.com`. A daily timer refreshes
  the live nftables sets; a rebuild resets them to the pins. Refresh the pins
  with `./update-cloudflare-ips.sh` and commit the diff.
- **`nixos-anywhere` is destructive.** Snapshot first.
- **`system.stateVersion` is set at install** and must not be bumped casually.
- **Secrets are not declarative.** Everything in the Nix store is world-readable,
  so the origin key, GHCR token and app secrets stay out-of-band in `/etc`. If
  you later want them declarative too, that is `sops-nix` or `agenix`.
- **A fresh host serves a self-signed certificate** until you run
  `install-origin-cert.sh`. Cloudflare returns 526 until then. This is
  deliberate — see step 4.
