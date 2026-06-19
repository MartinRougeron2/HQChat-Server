// PM2 process definition for the HQCAT WebSocket server.
// Usage on the VPS:
//   cd server/messages && npm install
//   pm2 start ../../deploy/ecosystem.config.js
//   pm2 save && pm2 startup   # survive reboots
//
// Secrets are read from server/messages/.env (dotenv) — do NOT commit them.
// Keep this file free of live keys; only non-secret config lives here.

module.exports = {
  apps: [
    {
      name: "hqcat-server",
      cwd: "./server/messages",
      script: "npx",
      args: "tsx server.ts",
      env: {
        NODE_ENV: "production",
        PORT: "8080",
      },
      restart_delay: 3000,
      max_restarts: 10,
      // Restart if memory balloons (FFI + audio buffers).
      max_memory_restart: "400M",
    },
    {
      // Always-on helper bot (a protocol client). On first run it prints its
      // public key — add that to EXEMPT_PUBLIC_KEYS in .env so it skips the
      // Stripe gate, then `pm2 restart hqcat-bot`.
      name: "hqcat-bot",
      cwd: "./server/messages",
      script: "npx",
      args: "tsx bot/bot.ts",
      env: {
        NODE_ENV: "production",
        SERVER_WS_URL: "wss://chat.martinrougeron.me/ws",
        BOT_USERNAME: "helper",
      },
      restart_delay: 3000,
      max_restarts: 10,
      max_memory_restart: "300M",
    },
  ],
};
