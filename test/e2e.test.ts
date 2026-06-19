import { test } from "node:test";
import { strict as assert } from "node:assert";
import { MessageTypesToReceive as In } from "../enums";
import { TestClient, loadCrypto } from "./helpers/test-client";

// End-to-end tests of the full user journey, driving TWO real protocol clients
// (the same crypto/handshake the Swift apps use) against a running server:
//   auth → transport keys → username → friend handshake → text → photo → receipt
//
// Requires:
//   - the native HQC lib (Linux/CI) — skipped otherwise
//   - a reachable server at TEST_WS_URL (default ws://localhost:8080/ws) with an
//     admission policy that lets fresh test identities in (ADMISSION_POLICY=open).
//     Point TEST_WS_URL at a self-hosted/local server or a test deployment.
// Skips cleanly when either is missing, so `npm test` stays green without infra.

const WS_URL = process.env.TEST_WS_URL || "ws://localhost:8080/ws";

test("e2e: two clients, full journey over a live server", async (t) => {
  let crypto;
  try {
    crypto = await loadCrypto();
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }

  const alice = new TestClient(crypto, WS_URL);
  try {
    await alice.connectAndAuth();
  } catch (e: any) {
    return t.skip(`no usable server at ${WS_URL} (${e?.message ?? e})`);
  }
  const bob = new TestClient(crypto, WS_URL);
  await bob.connectAndAuth();

  const suffix = Date.now().toString(36) + Math.floor(Math.random() * 1000);
  const aliceName = `e2e_a_${suffix}`;
  const bobName = `e2e_b_${suffix}`;

  try {
    await t.test("register usernames", async () => {
      await alice.setUsername(aliceName);
      await bob.setUsername(bobName);
    });

    await t.test("friend request + AES handshake establishes a secure channel", async () => {
      alice.addFriend(bobName);
      await bob.waitFor(In.FRIEND_REQUEST);
      bob.acceptInvite(aliceName);
      await Promise.all([
        alice.waitForSecureChannel(bobName),
        bob.waitForSecureChannel(aliceName),
      ]);
    });

    await t.test("text message A→B decrypts correctly", async () => {
      alice.sendMessage(bobName, "hello e2e 🔒");
      const m = await bob.nextMessage();
      assert.equal(m.from, aliceName);
      assert.equal(m.text, "hello e2e 🔒");
    });

    await t.test("text reply B→A decrypts correctly", async () => {
      bob.sendMessage(aliceName, "reply ✅");
      const m = await alice.nextMessage();
      assert.equal(m.from, bobName);
      assert.equal(m.text, "reply ✅");
    });

    await t.test("delivery receipt when recipient is online", async () => {
      const receipt = alice.waitFor(In.MESSAGE_DELIVERED);
      alice.sendMessage(bobName, "receipt please");
      await receipt;
      await bob.nextMessage(); // drain it
    });

    await t.test("photo (image_message, AES-only) A→B decrypts correctly", async () => {
      const content = "IMAGE:" + Buffer.from("fake-jpeg-bytes").toString("base64");
      alice.sendImage(bobName, content);
      const m = await bob.nextMessage();
      assert.equal(m.from, aliceName);
      assert.equal(m.imageContent, content);
    });

    await t.test("view-once photo carries its prefix end-to-end", async () => {
      const content = "IMAGE_ONCE:" + Buffer.from("secret-photo").toString("base64");
      alice.sendImage(bobName, content);
      const m = await bob.nextMessage();
      assert.equal(m.imageContent, content);
      assert.ok(m.imageContent!.startsWith("IMAGE_ONCE:"));
    });

    await t.test("/info advertises protocol + admission", async () => {
      const httpUrl = WS_URL.replace(/^ws/, "http").replace(/\/ws$/, "") + "/info";
      const res = await fetch(httpUrl);
      assert.equal(res.status, 200);
      const info: any = await res.json();
      assert.equal(typeof info.protocolVersion, "number");
      assert.ok(["open", "allowlist", "stripe"].includes(info.admission));
      assert.ok(Array.isArray(info.features));
    });
  } finally {
    alice.close();
    bob.close();
  }
});
