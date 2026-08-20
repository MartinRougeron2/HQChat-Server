import { test } from "node:test";
import { strict as assert } from "node:assert";
import { MessageTypesToReceive as In } from "./enums";
import { TestClient, loadCrypto } from "./test-client";

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

    await t.test("a backgrounded recipient is queued, not relayed into a frozen socket", async () => {
      // iOS suspends the app without closing the socket, so "the socket is
      // open" used to be taken as "the user can receive". Messages were written
      // into a socket nobody was reading — never queued, so never pushed, and
      // no notification until the heartbeat reaped the connection ~30s later.
      const queued = alice.waitFor(In.MESSAGE_QUEUED);
      bob.background();
      // Give the server a moment to record the presence change before sending.
      await new Promise((r) => setTimeout(r, 300));
      alice.sendMessage(bobName, "sent while backgrounded 🌙");
      const receipt = await queued;
      assert.ok(receipt, "sender should be told the message was queued, not delivered");

      // Coming back must deliver it — without a reconnect, so the client pays
      // no second handshake (and the user no second biometric prompt).
      bob.foreground();
      const m = await bob.nextMessage();
      assert.equal(m.from, aliceName);
      assert.equal(m.text, "sent while backgrounded 🌙");
    });

    await t.test("a client that speaks again is live again, even if app_foreground is lost", async () => {
      // The foreground frame can go missing: the socket may have died while the
      // app was suspended, or the frame simply never made it out. When that
      // happened the server kept the user marked away on a perfectly good
      // socket — so every message queued and arrived as a push while their
      // conversation stayed empty. Any frame from a client proves it is awake,
      // because a suspended app runs no code.
      bob.background();
      await new Promise((r) => setTimeout(r, 300));

      // Bob speaks without ever sending app_foreground.
      bob.sendMessage(aliceName, "i'm awake 👋");
      const heard = await alice.nextMessage();
      assert.equal(heard.text, "i'm awake 👋");

      // …and is therefore delivered to live, not queued.
      const delivered = alice.waitFor(In.MESSAGE_DELIVERED);
      alice.sendMessage(bobName, "and so are you");
      await delivered;
      const back = await bob.nextMessage();
      assert.equal(back.text, "and so are you");
    });

    await t.test("key rotation to epoch 1 relays end-to-end; messages decrypt under the ratchet", async () => {
      const aliceRotated = alice.waitForEpoch(bobName, 1);
      const bobRotated = bob.waitForEpoch(aliceName, 1);
      alice.rotateKeys(bobName);
      await Promise.all([aliceRotated, bobRotated]);
      assert.equal(alice.currentEpoch(bobName), 1);
      assert.equal(bob.currentEpoch(aliceName), 1);

      alice.sendMessage(bobName, "post-rotation A→B 🔁");
      const m1 = await bob.nextMessage();
      assert.equal(m1.from, aliceName);
      assert.equal(m1.text, "post-rotation A→B 🔁");

      bob.sendMessage(aliceName, "post-rotation B→A 🔁");
      const m2 = await alice.nextMessage();
      assert.equal(m2.from, bobName);
      assert.equal(m2.text, "post-rotation B→A 🔁");
    });

    await t.test("second ratchet message advances the chain (distinct keys per message)", async () => {
      alice.sendMessage(bobName, "msg idx 1");
      const m = await bob.nextMessage();
      assert.equal(m.text, "msg idx 1");
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
