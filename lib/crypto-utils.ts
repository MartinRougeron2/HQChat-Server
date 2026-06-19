import * as crypto from "crypto";

/**
 * Pure, dependency-free crypto helpers shared by the DB and Stripe layers.
 * Kept separate so they can be unit-tested without importing Redis.
 */

/**
 * Blind friendship identifier: a SHA-256 over the two public keys sorted, so
 * the server can check a friendship without storing who is friends with whom,
 * and so the hash is identical regardless of argument order.
 */
export function friendshipHash(pk1: string, pk2: string): string {
  const sorted = [pk1, pk2].sort().join("");
  return crypto.createHash("sha256").update(sorted).digest("hex");
}

/**
 * Blinded public key used as the Stripe customer identifier — the raw crypto
 * identity is never sent to the payment processor.
 */
export function blindedPk(pk: string): string {
  return crypto.createHash("sha256").update(pk).digest("hex");
}
