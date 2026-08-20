// Shared admission policy — decides whether an authenticated public key may use
// this server. Extracted from server.ts so the WS monolith AND the extracted
// auth server (auth/main.ts) enforce identical rules with no drift.

import { DB } from "../services/db/api";
import { StripeService } from "../services/stripe/api";
import { blindedPk } from "./crypto-utils";
import { logger } from "./logger";

//   open      — anyone who passes HQC auth (default; self-host friendly)
//   allowlist — only public keys in ADMISSION_ALLOWLIST (private/family servers)
//   stripe    — requires an active Stripe/StoreKit subscription (official server)
export const ADMISSION_POLICY = (process.env.ADMISSION_POLICY || "open").toLowerCase();
export const ADMISSION_ALLOWLIST = (process.env.ADMISSION_ALLOWLIST || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

export type Admission =
  | { ok: true }
  | { ok: false; reason: "payment"; checkoutUrl: string | undefined }
  | { ok: false; reason: "denied" };

/** Decide whether an authenticated public key may use this server. Exempt keys
 *  (e.g. the helper bot) always pass, regardless of policy. */
export async function checkAdmission(pkHex: string): Promise<Admission> {
  const exempt = (process.env.EXEMPT_PUBLIC_KEYS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (exempt.includes(pkHex)) return { ok: true };

  // Self-registered exemptions (the helper bot writes its own pk on startup; see
  // messages/bot/bot.ts). Survives the bot's identity/seed changing without any
  // operator editing EXEMPT_PUBLIC_KEYS. Best-effort: a Redis blip here must not
  // hard-fail admission for paying users, so fall through to the policy check.
  try {
    if (await DB.isAdmissionExempt(pkHex)) return { ok: true };
  } catch (e: any) {
    logger.error(`[admission] exempt-set lookup failed: ${e.message}`);
  }

  switch (ADMISSION_POLICY) {
    case "stripe": {
      // A StoreKit (iOS in-app purchase) OR a Stripe (web/macOS) subscription
      // both count as paid. Check the cheap StoreKit flag first so a verified
      // App Store subscriber isn't gated by the Stripe lookup.
      if (await DB.isStoreKitPremium(blindedPk(pkHex))) return { ok: true };
      const sub = await StripeService.syncAndGetStatus(pkHex);
      return sub.active ? { ok: true } : { ok: false, reason: "payment", checkoutUrl: sub.checkoutUrl };
    }
    case "allowlist":
      return ADMISSION_ALLOWLIST.includes(pkHex) ? { ok: true } : { ok: false, reason: "denied" };
    case "open":
    default:
      return { ok: true };
  }
}
