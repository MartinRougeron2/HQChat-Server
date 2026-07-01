# DissQus relay server.
#
# glibc base (bookworm), NOT Alpine/musl: lib/hqc.ts dlopen's the native
# post-quantum lib (lib/libhqc_x86.so) which links libc.so.6 — it will not
# load under musl. The image is therefore linux/amd64 (the .so is x86_64);
# build on the VM or with `--platform=linux/amd64`.
FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

# Install deps first for layer caching. tsx is a real *dependency* (not dev), so
# it's installed even with NODE_ENV=production — the server runs the TypeScript
# directly via `node --import tsx`. typescript/@types stay dev-only and are
# correctly omitted from the production image.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# App source (the native .so under lib/ is copied with it; see .dockerignore).
COPY . .

# Drop privileges. The bundled `node` user owns the workdir for any runtime
# writes (e.g. the bot's .bot-seed / .bot-state.json when no volume is mounted).
RUN chown -R node:node /app
USER node

EXPOSE 8080

# Liveness: the slim image has no curl/wget, so probe with node itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Run via `node --import tsx` rather than `npx tsx` or the `.bin/tsx` shebang:
#   - `npx` can touch an npm cache (breaks a read-only rootfs) / fetch on miss.
#   - execing `.bin/tsx` makes Node load the symlink path as the main module,
#     which fails to resolve.
# `--import tsx` resolves the tsx PACKAGE and registers its in-memory loader, so
# it works under read-only root + cap_drop: ALL + no-new-privileges (writes
# nothing outside the mounted volumes / tmpfs).
CMD ["node", "--import", "tsx", "server.ts"]
