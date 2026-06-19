# HQCAT — Production Deployment (Week 3)

Goal: server reachable at `wss://YOUR_DOMAIN/ws` over TLS, Redis persistent,
process auto-restarting, Stripe webhook live. Then point the apps at it and
live-test.

Prereqs you provide: a **VPS** (Linux x86, Ubuntu 24.04), a **domain**, and
your **live Stripe keys**.

---

## 1. VPS + base packages

```bash
ssh root@VPS_IP
adduser deploy && usermod -aG sudo deploy   # optional non-root user
ufw allow OpenSSH && ufw allow 80 && ufw allow 443 && ufw enable
apt update && apt install -y nginx redis-server         # no certbot — Cloudflare handles TLS
# Node 22 via nvm (as the deploy user)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install 22
npm i -g pm2
git clone YOUR_REPO_URL hqcat && cd hqcat
```

## 2. Redis persistence + password

Edit `/etc/redis/redis.conf`:

```
appendonly yes
appendfsync everysec
save ""
requirepass camilaestlabestdumonde$$$
```

```bash
sudo systemctl restart redis && sudo systemctl enable redis
 redis-cli -a camilaestlabestdumonde$$$ ping        # → PONG
 redis-cli -a camilaestlabestdumonde$$$ INFO persistence | grep aof_enabled   # → 1
```

## 3. Secrets

```bash
cp deploy/.env.example server/messages/.env
nano server/messages/.env   # fill STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, REDIS_URL
cd server/messages && npm install && cd ../..
```

## 4. Cloudflare DNS + TLS (no certbot)

Cloudflare terminates the public TLS and proxies WebSockets automatically.

1. **Cloudflare → DNS:** add an `A` record `@` (or a subdomain) → VPS IP,
   **Proxy status = Proxied (orange cloud)**. This gives the edge cert, WAF,
   and WebSocket support.
2. **Cloudflare → SSL/TLS → Overview:** set encryption mode to **Full (strict)**
   (recommended) and enable **Always Use HTTPS**.
3. **Cloudflare → SSL/TLS → Origin Server → Create Certificate.** Save the cert
   and key on the VPS:
   ```bash
   sudo mkdir -p /etc/ssl/cloudflare
   sudo nano /etc/ssl/cloudflare/origin.pem   # paste the certificate
   sudo nano /etc/ssl/cloudflare/origin.key   # paste the private key
   sudo chmod 600 /etc/ssl/cloudflare/origin.key
   ```
4. Install the nginx site:
   ```bash
   sudo cp deploy/nginx.conf /etc/nginx/sites-available/hqcat
   sudo sed -i 's/martinrougeron.me/chat.martinrougeron.me/g' /etc/nginx/sites-available/hqcat
   sudo ln -s /etc/nginx/sites-available/hqcat /etc/nginx/sites-enabled/hqcat
   sudo nginx -t && sudo systemctl reload nginx
   ```

> **Simplest path (less secure):** set the Cloudflare SSL mode to **Flexible**,
> delete the `listen 443` block from `nginx.conf`, and skip steps 2–3. Cloudflare
> then talks to the origin over plain HTTP on port 80.

> **Notes:**
>
> - Cloudflare's free plan supports WebSockets — `wss://your.domain/ws` works through the proxy with no extra config.
> - Cloudflare drops idle proxied WebSockets (~100s). The app's 30s heartbeat keeps them alive, so this is already handled.
> - To log real client IPs, add Cloudflare's IP ranges via `set_real_ip_from` (optional; the config already forwards `CF-Connecting-IP`).

## 5. Run the server under PM2

```bash
pm2 start deploy/ecosystem.config.js
pm2 save && pm2 startup    # run the printed command to enable boot start
pm2 logs hqcat-server      # watch auth/heartbeat logs
curl https://chat.martinrougeron.me/health   # → ok
```

## 6. Stripe webhook

Stripe Dashboard → Developers → Webhooks → Add endpoint:

- URL: `https://chat.martinrougeron.me/stripe/webhook`
- Events: `customer.subscription.created`, `.updated`, `.deleted`
  Copy the signing secret into `STRIPE_WEBHOOK_SECRET` in `.env`, then `pm2 restart hqcat-server`.
  Test locally first: `stripe listen --forward-to localhost:8080/stripe/webhook`.

## 7. Point the apps at production

The client URL is configurable (see `ServerConfig` in `WebSocketManager.swift`).
Either:

- Add `ServerWebSocketURL = wss://chat.martinrougeron.me/ws` to each target's Info.plist
  (`INFOPLIST_KEY_ServerWebSocketURL`), **or**
- Edit the Release fallback in `ServerConfig` (`wss://CHANGE_ME.example.com/ws`).
  Debug builds still use `ws://localhost:8080/ws`.

## 8. Monitoring (optional, free)

UptimeRobot → HTTP(s) monitor on `https://chat.martinrougeron.me/health`, 5-min interval.

---

## Live test checklist

- Two profiles (iPhone + Mac, or two sims) connect over `wss://`.
- Send messages both ways; offline one client, send, reconnect → queued messages flush.
- Delivery ticks: ✓ when peer online, 🕐 queued when offline → flips on reconnect.
- Kill the server (`pm2 stop`) → clients show "Reconnecting…"; `pm2 start` → they recover.
- Subscription: unpaid profile shows the subscribe screen; after paying, the
  webhook flips the tier and a reconnect lets them in.
