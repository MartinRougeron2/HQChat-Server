import { test } from "node:test";
import assert from "node:assert";
import { appAccountTokenForPk } from "../services/storekit/api";

// The appAccountToken binds a StoreKit purchase to a public key. The server and
// the iOS client (SubscriptionManager.appAccountToken(forPublicKeyHex:)) MUST
// derive the identical UUID or the server can't map a transaction to its user.
// This pins the derivation so a change on either side is caught here.
test("appAccountTokenForPk is a deterministic RFC-4122 v4 UUID", () => {
  const tok = appAccountTokenForPk("abcd1234");
  assert.strictEqual(tok, "e9cee71a-b932-4de8-a333-8d08be4de9df");
  // version nibble = 4, variant nibble in {8,9,a,b}
  assert.strictEqual(tok.charAt(14), "4");
  assert.match(tok.charAt(19), /[89ab]/);
  // stable across calls
  assert.strictEqual(appAccountTokenForPk("abcd1234"), tok);
});
