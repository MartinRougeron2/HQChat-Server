// Centralized config loading, Docker-secret resolution, and fail-fast
// validation. This module is intentionally side-effecting at import time so it
// can run BEFORE any service module reads process.env. Import it FIRST in
// server.ts / bot.ts (`import "./lib/config"`).
//
// Load order matters:
//   1. dotenv  — fills process.env from a .env file (ENV_FILE overrides path).
//   2. _FILE   — resolves the Docker/compose "secrets" pattern: any FOO_FILE
//                env var is read from disk and its contents become FOO. This
//                lets compose mount secrets at /run/secrets/* without ever
//                putting the plaintext value in the environment or an image.
//   3. assertConfig() — called explicitly by the entrypoint to fail fast.

import * as fs from "fs";

// 1. dotenv (best-effort: in Docker the env comes from compose, not a file).
try {
  const dotenv = require("dotenv");
  dotenv.config({ quiet: true, ...(process.env.ENV_FILE ? { path: process.env.ENV_FILE } : {}) });
} catch {
  // dotenv not installed / no file — fine when env is injected by the runtime.
}

// 2. Resolve the *_FILE secrets convention (Docker secrets / compose `secrets:`).
//    For every FOO_FILE that points at a readable file, set FOO to its trimmed
//    contents unless FOO is already explicitly set (explicit env wins).
for (const key of Object.keys(process.env)) {
  if (!key.endsWith("_FILE")) continue;
  const base = key.slice(0, -"_FILE".length);
  if (process.env[base]) continue; // explicit value takes precedence
  const path = process.env[key];
  if (!path) continue;
  try {
    process.env[base] = fs.readFileSync(path, "utf8").trim();
  } catch (err: any) {
    // Loud, because a missing secret file is almost always a deploy mistake.
    console.error(`⚠️  config: ${key}=${path} could not be read: ${err.message}`);
  }
}

// 2b. Convenience for Docker: if REDIS_URL isn't set but a REDIS_PASSWORD is
//     (typically via REDIS_PASSWORD_FILE → a compose secret), assemble the URL
//     so the same single secret feeds both the redis container and the server.
if (!process.env.REDIS_URL && process.env.REDIS_PASSWORD) {
  const host = process.env.REDIS_HOST || "127.0.0.1";
  const port = process.env.REDIS_PORT || "6379";
  process.env.REDIS_URL = `redis://:${encodeURIComponent(process.env.REDIS_PASSWORD)}@${host}:${port}`;
}

const isProd = process.env.NODE_ENV === "production";

/** Throw with a combined message listing every missing/invalid setting, so a
 *  misconfigured box fails immediately at boot instead of at first request. */
export function assertConfig(): void {
  const errors: string[] = [];
  const warnings: string[] = [];
  const require = (name: string, why: string) => {
    if (!process.env[name]?.trim()) errors.push(`${name} is required (${why}).`);
  };

  const policy = (process.env.ADMISSION_POLICY || "open").toLowerCase();

  if (policy === "stripe") {
    require("STRIPE_SECRET_KEY", "ADMISSION_POLICY=stripe");
    require("STRIPE_WEBHOOK_SECRET", "ADMISSION_POLICY=stripe; verifies webhook signatures");
    require("PUBLIC_BASE_URL", "ADMISSION_POLICY=stripe; used to build Stripe redirect URLs");
    // StoreKit (iOS IAP) is optional, but if partially configured it will
    // silently fail to verify — so demand the full set once any of it is set.
    const skKeys = ["STOREKIT_BUNDLE_ID", "STOREKIT_PRODUCT_ID", "STOREKIT_ROOT_CERTS_DIR"];
    if (skKeys.some((k) => process.env[k]?.trim())) {
      for (const k of skKeys) require(k, "StoreKit verification is partially configured");
    }
  } else if (policy === "allowlist") {
    if (!process.env.ADMISSION_ALLOWLIST?.trim())
      warnings.push("ADMISSION_POLICY=allowlist but ADMISSION_ALLOWLIST is empty — nobody can join.");
  } else if (policy !== "open") {
    errors.push(`ADMISSION_POLICY="${policy}" is invalid (expected open | allowlist | stripe).`);
  }

  // APNs: all-or-nothing. Partial config means push silently breaks.
  const apnsKeys = ["APNS_KEY_ID", "APNS_TEAM_ID", "APNS_KEY_P8"];
  const apnsSet = apnsKeys.filter((k) => process.env[k]?.trim());
  if (apnsSet.length > 0 && apnsSet.length < apnsKeys.length) {
    errors.push(`APNs is partially configured (${apnsSet.join(", ")}) — set all of ${apnsKeys.join(", ")} or none.`);
  }

  // Redis without a password in production is a common foot-gun (open 6379).
  const redisUrl = process.env.REDIS_URL || "";
  if (isProd && redisUrl && !/:[^@/]+@/.test(redisUrl) && !redisUrl.includes("@")) {
    warnings.push("REDIS_URL has no password in production — ensure Redis is firewalled / requirepass is set.");
  }
  if (isProd && /CHANGE_ME/i.test(redisUrl)) {
    errors.push("REDIS_URL still contains the placeholder CHANGE_ME password.");
  }

  for (const w of warnings) console.warn(`⚠️  config: ${w}`);
  if (errors.length) {
    console.error("\n❌ Invalid configuration — refusing to start:\n  - " + errors.join("\n  - ") + "\n");
    process.exit(1);
  }
}
