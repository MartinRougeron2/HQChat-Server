import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { DB } from "../db/api";
import { blindedPk } from "../../lib/crypto-utils";

/**
 * StoreKit (App Store) subscription verification — the iOS in-app purchase path
 * (App Store Guideline 3.1.1). The iOS client buys an auto-renewable
 * subscription via StoreKit and POSTs the signed transaction (a JWS) to
 * /storekit/verify. We verify Apple's signature, confirm the purchase is bound
 * to the caller's public key, and flip the account to premium.
 *
 * The Stripe/web flow is untouched — this is a parallel payment path. Admission
 * (checkAdmission in server.ts) treats a StoreKit subscription OR a Stripe
 * subscription as paid.
 *
 * SETUP REQUIRED before this works in production (no secrets live in the repo):
 *   - `npm i @apple/app-store-server-library`
 *   - env: STOREKIT_BUNDLE_ID, STOREKIT_PRODUCT_ID, STOREKIT_ENV
 *     (Production|Sandbox), STOREKIT_APP_APPLE_ID, and STOREKIT_ROOT_CERTS_DIR
 *     pointing at a folder of Apple's downloaded root .cer files.
 * We NEVER trust an unverified transaction: if the library/config is missing,
 * verification throws and the endpoint rejects the receipt.
 */

const BUNDLE_ID = process.env.STOREKIT_BUNDLE_ID || "";
const PRODUCT_ID = process.env.STOREKIT_PRODUCT_ID || "me.martinrougeron.dissqus.premium.monthly";
const APP_APPLE_ID = process.env.STOREKIT_APP_APPLE_ID ? Number(process.env.STOREKIT_APP_APPLE_ID) : undefined;
const ROOT_CERTS_DIR = process.env.STOREKIT_ROOT_CERTS_DIR || "";

/**
 * RFC-4122 v4 UUID derived from the first 16 bytes of SHA-256(pkHex). MUST
 * match the iOS client's SubscriptionManager.appAccountToken(forPublicKeyHex:)
 * so the purchase is cryptographically bound to the identity that made it.
 */
export function appAccountTokenForPk(pkHex: string): string {
  const d = crypto.createHash("sha256").update(pkHex, "utf8").digest();
  const b = Buffer.from(d.subarray(0, 16));
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x40; // version 4
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80; // RFC-4122 variant
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

let _verifier: any | null = null;

/** Build (once) Apple's SignedDataVerifier from the official library. Throws a
 *  clear error if the library or root certs aren't configured. */
function getVerifier(): any {
  if (_verifier) return _verifier;

  let lib: any;
  try {
    lib = require("@apple/app-store-server-library");
  } catch {
    throw new Error(
      "StoreKit verification unavailable — run `npm i @apple/app-store-server-library`"
    );
  }
  if (!BUNDLE_ID) throw new Error("STOREKIT_BUNDLE_ID is not set");
  if (!ROOT_CERTS_DIR) throw new Error("STOREKIT_ROOT_CERTS_DIR is not set");

  const certs = fs
    .readdirSync(ROOT_CERTS_DIR)
    .filter((f) => f.endsWith(".cer") || f.endsWith(".der") || f.endsWith(".pem"))
    .map((f) => fs.readFileSync(path.join(ROOT_CERTS_DIR, f)));
  if (certs.length === 0) throw new Error(`No Apple root certs found in ${ROOT_CERTS_DIR}`);

  // Environment enum keys are upper-case (PRODUCTION / SANDBOX).
  const env = (process.env.STOREKIT_ENV || "Production").toUpperCase();
  _verifier = new lib.SignedDataVerifier(
    certs,
    true, // enableOnlineChecks (OCSP)
    lib.Environment[env] ?? lib.Environment.PRODUCTION,
    BUNDLE_ID,
    APP_APPLE_ID
  );
  return _verifier;
}

export const StoreKitService = {
  /**
   * Verify a signed transaction (JWS), ensure it belongs to `pkHex` and is
   * active, then persist premium for the blinded pk. Returns true if premium.
   */
  async verifyAndApply(jws: string, pkHex: string): Promise<boolean> {
    if (typeof jws !== "string" || !/^[0-9a-fA-F]+$/.test(pkHex)) return false;

    // Apple-signed → tamper-proof. Throws if it can't be verified.
    const tx = await getVerifier().verifyAndDecodeTransaction(jws);

    // Right app + product.
    if (BUNDLE_ID && tx.bundleId && tx.bundleId !== BUNDLE_ID) return false;
    if (tx.productId !== PRODUCT_ID) return false;

    // Bind the purchase to the caller's identity via appAccountToken.
    const expected = appAccountTokenForPk(pkHex);
    if (!tx.appAccountToken || String(tx.appAccountToken).toLowerCase() !== expected.toLowerCase()) {
      return false;
    }

    const now = Date.now();
    const active = !tx.revocationDate && (!tx.expiresDate || tx.expiresDate > now);

    const bpk = blindedPk(pkHex);
    await DB.setStoreKitPremium(bpk, active ? (tx.expiresDate ?? 0) : 0);
    await DB.updateUserTier(bpk, active ? "premium" : "free");
    return active;
  },
};
