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
//   3. assertConfig(needs) — called explicitly by the entrypoint to fail fast.
//
// `needs` exists because the services no longer want the same things. Only
// app-api talks to Stripe; only auth mails claim codes. Demanding both of both
// would force every service to hold every secret, which is the opposite of what
// splitting them was for.

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

const isProd = process.env.NODE_ENV === "production";

/** What the calling service actually uses. Checks for a capability nobody
 *  declared are skipped — an auth server with no Stripe key is correct, not
 *  broken. */
export type ConfigNeed = "stripe" | "mail";

/** Exit with a combined message listing every missing/invalid setting, so a
 *  misconfigured box fails immediately at boot instead of at first request. */
export function assertConfig(needs: ConfigNeed[] = []): void {
  const errors: string[] = [];
  const warnings: string[] = [];
  const require = (name: string, why: string) => {
    if (!process.env[name]?.trim()) errors.push(`${name} is required (${why}).`);
  };

  const policy = (process.env.ADMISSION_POLICY || "open").toLowerCase();

  if (policy === "stripe") {
    if (needs.includes("stripe")) {
      require("STRIPE_SECRET_KEY", "ADMISSION_POLICY=stripe");
      require("STRIPE_WEBHOOK_SECRET", "ADMISSION_POLICY=stripe; verifies webhook signatures");
      require("PUBLIC_BASE_URL", "ADMISSION_POLICY=stripe; used to build Stripe redirect URLs");
    }
    if (needs.includes("mail")) {
      // Mail is not optional for the service that owns /claim/*: a subscription
      // is claimed with a code sent by email, so a server that cannot send is a
      // server nobody can finish paying for. Refuse to boot rather than sell
      // into a dead end.
      require("RESEND_API_KEY", "ADMISSION_POLICY=stripe; subscription claim codes are emailed");
      require("MAIL_FROM", "ADMISSION_POLICY=stripe; the From address for claim codes");
      if (isProd && !process.env.OTP_PEPPER?.trim()) {
        errors.push("OTP_PEPPER is required in production (without it a database dump yields every pending claim code).");
      }
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

  // The database is not optional for any service in this stack — it IS the
  // state. A missing URL used to be survivable because ioredis defaulted to
  // localhost; nothing defaults now, so say so at boot rather than at the first
  // request.
  const databaseUrl = process.env.DATABASE_URL || "";
  require("DATABASE_URL", "every service reads and writes Postgres");
  if (isProd && databaseUrl) {
    // `sslmode=require` encrypts but does not authenticate the server, which is
    // DigitalOcean's default and not enough on its own: the CA is on the host
    // (PGSSLROOTCERT), so there is no reason to accept anything weaker.
    if (!/sslmode=verify-full/.test(databaseUrl)) {
      warnings.push(
        "DATABASE_URL does not request sslmode=verify-full — the connection is encrypted but the server is not authenticated."
      );
    }
    if (!process.env.PGSSLROOTCERT?.trim()) {
      warnings.push("PGSSLROOTCERT is unset — verify-full cannot be honoured without the cluster CA.");
    }
    if (/CHANGE_ME/i.test(databaseUrl)) {
      errors.push("DATABASE_URL still contains the placeholder CHANGE_ME password.");
    }
  }

  // The test account is a real hole in the paid door, and the reason it is safe
  // is that everyone running the server knows it is open. Say so at every boot
  // that has it enabled, so it is never a surprise found in a code read.
  if (needs.includes("mail")) {
    const testEmail = (process.env.TEST_ACCOUNT_EMAIL ?? "test@test.test").trim();
    if (testEmail) {
      warnings.push(
        `TEST_ACCOUNT_EMAIL=${testEmail} is enabled — that address links any number of devices ` +
        `with a fixed code and no payment. Set TEST_ACCOUNT_EMAIL= (empty) to close it.`
      );
    }
  }

  for (const w of warnings) console.warn(`⚠️  config: ${w}`);
  if (errors.length) {
    console.error("\n❌ Invalid configuration — refusing to start:\n  - " + errors.join("\n  - ") + "\n");
    process.exit(1);
  }
}
