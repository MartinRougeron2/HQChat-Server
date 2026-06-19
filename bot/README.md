# DissQus helper bot

An always-on protocol client (`@helper`) that users can add as a friend and
message. It speaks the full protocol — HQC auth, AES secure-channel handshake,
HQC+AES message crypto — so its replies are end-to-end encrypted like any user.

Runs on the **VPS** (needs the Linux HQC library). Managed by PM2 alongside the
server (`deploy/ecosystem.config.js` → `hqcat-bot`).

## First-time setup

1. Start it once so it generates and saves its identity:
   ```bash
   cd server/messages && npm run bot
   ```
   It prints its **public key** (and saves the seed to `bot/.bot-seed`).

2. Copy the **full** public key from the log into `server/messages/.env`:
   ```
   EXEMPT_PUBLIC_KEYS=<bot_public_key_hex>
   ```
   (comma-separated if you add more exempt keys later). This lets the bot skip
   the Stripe subscription gate.

3. Restart the server so the exemption takes effect, then run the bot under PM2:
   ```bash
   pm2 restart hqcat-server
   pm2 start deploy/ecosystem.config.js --only hqcat-bot   # or just `pm2 start ...`
   pm2 save
   ```

## Using it
In the app, add **`helper`** (or your `BOT_USERNAME`) as a friend. Once the
secure channel establishes, send:
- `/help` · `/ping` · `/echo <text>` · `/time` · `/about`

## Files (git-ignored — they're secrets)
- `.bot-seed` — the bot's 32-byte identity seed (keeps the same public key across restarts)
- `.bot-state.json` — per-friend public keys + derived AES keys

## Env
| var | default |
|-----|---------|
| `SERVER_WS_URL` | `wss://chat.martinrougeron.me/ws` |
| `BOT_USERNAME`  | `helper` |
| `BOT_SEED`      | (optional) hex seed; otherwise generated + saved |
