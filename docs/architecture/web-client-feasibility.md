# Web client feasibility — verdict

**Question (v2 item 16):** can DissQus run in a browser, and if so should the
Stripe/account flow move to the web with the iOS app linking via an OTP?

**Verdict: no full web messaging client. Yes to a narrow account-and-payment
web surface — but it is not worth building for v2 as things stand.**

This is a written spike, not an implementation. Nothing here was built.

---

## 1. HQC in the browser

**Technically possible, practically heavy.**

The protocol is built on a native HQC IND-CCA2 KEM
(`native/hqc/lib/src/low_wrap.c`, bound via koffi on the server and via
`HQC.xcframework` / `libhqc_wrap.dylib` on Apple). It is plain C with no OS
dependencies beyond an entropy source, so an Emscripten target is a normal
addition to `native/hqc/lib/src/rebuild_hqc.sh`, which already builds four
targets from one pinned upstream revision.

What makes it awkward is the parameter set. HQC-256 sizes
(`services/server/lib/hqc.ts`):

| | bytes |
|---|---|
| public key | 7 237 |
| secret key | 7 333 |
| KEM ciphertext | 14 421 |
| shared secret | 32 |

The current native artefacts are 64–92 KB (`libhqc_5_ref_*.a`,
`libhqc_x86.so`), so a WASM module in the low hundreds of KB is a reasonable
expectation — acceptable on its own. The real costs are elsewhere:

- **A fifth build target to keep in lockstep.** `rebuild_hqc.sh` exists
  precisely because HQC's sampling changes between upstream revisions and a
  build from one revision does not interoperate with another. Every rebuild
  would now also have to ship a new WASM bundle to every open browser tab, in
  step with the server, the bot, and both apps.
- **Constant-time guarantees do not survive the trip.** The reference
  implementation's timing properties are argued about compiled C. WASM plus a
  JIT is a different execution model, and the audit already tracks side-channel
  concerns. Claiming post-quantum security in a browser would need work nobody
  has done.

## 2. Key storage — this is the blocker

On Apple the identity secret key lives in the Keychain under
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `.userPresence`
(`Services/ProfileManager.swift`), so reading it requires the device owner to be
present. There is no browser equivalent. The options are IndexedDB (readable by
any script that achieves XSS, and by anything with local disk access) or
non-extractable WebCrypto keys — which cannot wrap a custom KEM's secret key.

For an app whose entire proposition is "keys never leave your device, gated by
biometrics", moving the identity key into browser storage is a downgrade that
undercuts the product rather than extending it.

## 3. No certificate pinning in a browser

`TLSPinningDelegate` (`Services/WebSocketManager.swift:403`) fails closed against
a proxy or MITM certificate when `ServerPinnedSPKIHashes` is configured. A browser
cannot do this: it trusts the user's root store, including any corporate or
locally installed CA.

This matters less than it first appears — the HQC challenge–response
authenticates the *server relationship* independently of TLS, and message content
is end-to-end encrypted under keys the server never holds. A MITM sees ciphertext.
But it does remove a layer the apps have, and combined with §2 the browser
threat model is meaningfully weaker, not equivalent.

## 4. The narrower path: account + Stripe on web, iOS links by OTP

This avoids §1–§3 entirely, because no HQC handshake and no identity key are
involved. It is genuinely buildable:

- `services/server/api/main.ts` is already a real REST API behind bearer session
  auth, and `services/server/services/web/subscribe.ts` already server-renders
  the Stripe "linking code" flow (paste `SHA-256(pkHex)` → Stripe Checkout).
- An OTP would replace the paste-the-code step: the app shows a short code, the
  web page consumes it, the webhook flips the tier under the blinded pk.

**But it solves a problem v2 does not have.** Both `/subscribe` and
`/stripe/webhook` are gated on `ADMISSION_POLICY === "stripe"`
(`api/main.ts:66,88`), and `infra/deploy/docker-compose.yml` hardcodes
`ADMISSION_POLICY: open` with the Stripe secrets commented out. They are dead
code in production today: v1 deliberately gatekeeps cost with a $0.99 paid iOS
app instead of a subscription. Building a web payment flow means first
re-deciding the monetization model — that is a product call, not an engineering
one, and it should be made on its own merits rather than as a side effect of
"can we do web?".

## 5. Recommendation

1. **Drop full web messaging.** The key-storage problem (§2) has no answer that
   preserves the product's core claim. Revisit only if the threat model
   deliberately changes.
2. **Keep the account/payment web path on the shelf.** It is ~1–2 weeks of work
   and the server side largely exists, but it presupposes a return to
   subscriptions. Reopen it if and when the paid-app model stops working.
3. **If a web presence is wanted sooner**, the cheapest useful step is extending
   the existing Cloudflare Worker landing page (`apps/web/src/index.js`) — no new
   infrastructure, no crypto, no new threat model.

## What would change this verdict

- A browser API for non-extractable custom-KEM key material, or a WebAuthn-based
  key-wrapping scheme good enough to hold the identity secret.
- A decision to reinstate subscriptions, which would make §4 load-bearing.
- A move to a smaller HQC parameter set, which would shrink §1's costs but not
  §2's.
