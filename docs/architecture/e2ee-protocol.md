# The end-to-end encryption protocol

The normative description of what clients speak to each other. Until this
document existed the protocol was defined by three source files and a vector
file, which meant "what does the wire look like" could only be answered by
reading two implementations and hoping they agreed.

Implemented by [`lib/double-ratchet.ts`](../../services/server/lib/double-ratchet.ts) /
`DoubleRatchet.swift` (derivations),
[`lib/ratchet-session.ts`](../../services/server/lib/ratchet-session.ts) /
`RatchetSession.swift` (state machine),
and [`lib/envelope.ts`](../../services/server/lib/envelope.ts) /
`ConversationEnvelopeV2.swift` (wire format).

Both implementations assert the same vectors —
[`double-ratchet-vectors.json`](../../services/server/test/helpers/double-ratchet-vectors.json),
[`envelope-vectors.json`](../../services/server/test/helpers/envelope-vectors.json)
and [`identity-vectors.json`](../../services/server/test/helpers/identity-vectors.json) —
and both **read** those files rather than copying values into source. The last of
those is also asserted against a live Postgres, because the client identifier has
a third implementation: `pk_digest` in the schema.

---

## 1. What this replaces, and why

v1 was a symmetric ratchet with an occasional re-key. Three things were wrong
with it, and all three were structural rather than bugs:

- **No ephemeral keys.** Every shared secret — at channel setup and at every
  rotation — was a KEM encapsulation to the peer's long-term pinned key. KEM
  decapsulation is deterministic, so one leaked identity secret plus a recorded
  transcript recomputed every root, chain key and message key that conversation
  ever used. Deleting message keys after use bought nothing, because they were
  recomputable from ciphertexts the network had already seen.
- **The root did not chain.** The new root was derived from two fresh seeds and
  nothing else, so "epochs" were independent re-keys sitting side by side.
- **The first message was not ratcheted, and usually no message ever was.**
  Epoch 0 was a static AES key, and the only rotation triggers were a manual
  button and a 100-message counter — so a conversation under 100 messages lived
  its entire life under one key, with no forward secrecy and no replay
  protection.

## 2. Keys and names

### The client identifier

```
id = SHA-256( lowercase-hex(publicKey) )        // 64 hex characters
```

Everything that **names** a client is this: the MQTT client id and username, the
EMQX ACL row, every topic string, the envelope's `sender`, every peer-addressed
route parameter, the friend graph. The 7237-byte public key is kept only where
the key itself is needed — encapsulating to it, and the safety number.

The identifier used to be the key itself: 14474 characters. That broke everything
with a length limit, most consequentially the broker's admin API, where
`DELETE /clients/{id}` built a ~14.5 kB URL and was answered `414 URI Too Long`
every time — so *surgical revocation never once worked on this deployment*
([`emqx-revocation.test.ts`](../../services/server/test/emqx-revocation.test.ts)
pins the fix). The digest is not new: `001_schema.sql` had already been forced to
index every identity as `pk_digest(pk)`, which is precisely this value; the change
promotes it from an index expression to the identifier.

**An id is a commitment to the key.** Anyone holding a key can compute its id, so
an id is a *name* and never an authenticator — but the converse is what matters:
given an id, a key can be **checked**.

```
SHA-256(hex(receivedPk)) == knownId   ⟹  this is the key that id names
```

Second-preimage resistance means no substitute survives. So the graph carries
ids, and the full key travels twice per relationship — at friend-add
(`GET /peer/{id}/key`) and on the `init` frame (`senderPk`) — and is **verified on
arrival both times**. A key that fails the check is refused, never pinned.

⚠️ A client that skips that check has re-created the MITM this design closes.
Both do it: `keyMatchesId` in TypeScript, `PeerID.matches` in Swift.

### Key material

| Key | Lifetime | Job |
|---|---|---|
| Identity (HQC) | permanent, TOFU-pinned | authenticates the peer; contributes **one** secret to the initial root |
| Medium-term prekey | rotated (7 days) | forward secrecy with a rotation-length window; the fallback when one-time keys run out |
| One-time prekey | single use | forward secrecy that ends when the responder consumes it |
| Ratchet keypair | one direction-flip | the asymmetric ratchet step |

HQC is a KEM, not a signature scheme, so prekeys **cannot be signed** — and do
not need to be. Following PQXDH, the initiator encapsulates to *both* the pinned
identity key and the prekey, and mixes both secrets into the root. A substituted
prekey yields an attacker nothing, because they cannot produce `ss_id`. Prekey
authenticity is therefore not a required property, which is what avoids adding a
post-quantum signature scheme to the build.

**What the server can do:** withhold one-time keys, forcing the weaker
medium-term fallback. That narrows a forward-secrecy window; it does not affect
confidentiality. What it **cannot** do is substitute an identity key, because the
id commits to it.

### A new key is a new identity

The identifier *is* the key, so "this contact re-keyed" is not representable: a
different key is a different id is a different contact. The client models that
as the old identity having **vanished** —

- the old contact row is kept, unreachable and read-only. Never auto-deleted,
  never auto-merged;
- the new identity arrives as a **separate contact** needing its own
  verification. No inherited `keyVerified`;
- the copy says how this happens — reinstall, account reset, a new device — and
  that if the person did none of those, someone may be using their name.

Detection is the username fallback in `DirectorySync`: a lookup *by id* misses
exactly when the key changed, which is why a contact row carries both.

## 3. Establishing a session

```
initiator                                            responder
  fetch identity_pk for the peer's id, VERIFY it hashes to that id
  claim bundle {medium_pk, onetime_pk?}
  (ct_id, ss_id) = Encap(identity_pk)     ← pinned; authenticates
  (ct_mt, ss_mt) = Encap(medium_pk)
  (ct_ot, ss_ot) = Encap(onetime_pk)      ← when one was available

  root_0, chain = HKDF(ss_id ‖ ss_mt ‖ ss_ot?, "hqchat/v2/init/{root,chain}")
  generate ratchet keypair (rk, rk_sec)

  ── init frame: {ct_id, ct_mt, ct_ot?, otId?, rk, senderPk}
                 + a sealed message ─────────────────────────────►
                                        CHECK sha256(senderPk) == sender
                                        decapsulate all three
                                        derive the same root_0 and chain
                                        chain becomes the RECEIVING chain
```

`senderPk` is why a responder needs no round trip: an `init` is by definition the
frame from someone this device may never have fetched a key for. It is refused
unless it hashes to `sender`, so it cannot introduce a key the id does not
already commit to.

Roles are asymmetric only for the first message, which removes the sorted-seed
symmetry v1 needed. The initiator's first chain comes straight out of `root_0`;
the responder performs the first true ratchet step when it replies.

**The first message is sendable while the peer is offline.** It carries the
handshake, so no live round trip is required.

## 4. Ratcheting

- **Root chain:** `(root', ck) = HKDF(root ‖ ss, "hqchat/v2/{root,chain}")`. The
  new root depends on the old one, so an attacker who learns the state at step
  *n* cannot run it backwards, and one who missed a step cannot rejoin using
  later ciphertexts alone.
- **Asymmetric step.** A DH ratchet cannot be transliterated: with a KEM the
  *encapsulator* picks the secret and must transmit a ciphertext. A stepping
  header therefore carries both a fresh ratchet public key and a ciphertext
  encapsulated to the peer's current one.
- **Symmetric chain:** `mk = HKDF(ck, ".../msg")`, `ck' = HKDF(ck, ".../ck")`,
  with a bounded skipped-key cache for out-of-order and offline delivery.

### Step frequency

A step costs a public key (7237 B) plus a ciphertext (14421 B) — about **29 kB
base64**. Stepping on every direction flip is strongest and is what Signal does,
but in a fast exchange that is 29 kB per turn on a phone.

So a flip steps only when the current chain has run `RATCHET_MAX_MESSAGES_PER_CHAIN`
(32) messages or lived `RATCHET_MIN_STEP_INTERVAL` (60 s), whichever comes first
— and always on the responder's first reply. **These numbers are the
post-compromise-security window**: a compromise heals within one step.

## 5. Wire format

```jsonc
// init — first contact. Topic: u/{peerId}/inbox
{ "v":2, "t":"init", "sender":"<64 hex — the client id>", "msgId":"…",
  "senderPk":"<14474 hex — the initiator's key; MUST hash to `sender`>",
  "ctId":"<b64>", "ctMt":"<b64>", "ctOt":"<b64>|absent", "otId":<int|absent>,
  "rk":"<b64>", "cid":"<32 hex>", "n":0, "pn":0, "payload":"<b64 AES-GCM>" }

// msg — everything after. Topic: c/{friendshipHash(idA, idB)}
{ "v":2, "t":"msg", "sender":"<64 hex — the client id>", "msgId":"…",
  "rk":"<b64>?", "kemCt":"<b64>?", "cid":"<32 hex>", "n":<int>, "pn":<int>,
  "payload":"<b64 AES-GCM>" }
```

`sender` is **exactly 64 lowercase hex** — the client id. It carried the whole
public key, under a `1–20000 hex` bound wide enough to admit a nibble, a chain id
or 10 kB of anything; a fixed width is what lets a wrong-shaped identifier be
refused rather than looked up and not found.

`senderPk` appears on `init` alone and is deliberately **not** in the canonical
header. `sender` is bound as AAD and `senderPk` is bound to `sender` by
arithmetic, so binding it twice would break every existing vector for nothing.

`cid` is on **every** frame. It is `SHA-256(rk)[0..16]` of the sender's current
ratchet key, and it exists because `n` restarts at 0 on each chain: a bare
straggler from the sender's previous chain would otherwise be read against the
new one, yielding a wrong key and advancing a chain that had no claim on it.
Signal solves this by putting the whole ratchet key in every header; at 7237
bytes that is not affordable here, so the header carries the digest and the full
key travels only on a step.

### Delivery topics

An `init` goes to the peer's **inbox** (`u/{peer}/inbox`); everything else to the
shared conversation topic. This is about delivery, not secrecy: MQTT drops a
publish to a topic nobody has subscribed to, which is exactly what a brand-new
friendship is. Clients subscribe to their own inbox on connect with
`cleanSession = false`, so the broker queues it for an offline peer. The
friendship grant carries `publish` on the peer's inbox.

### The canonical header (AAD)

Every field except `payload` is bound as AES-GCM additional authenticated data.
The header is what *selects* the key, so it is necessarily read before the
payload it selects for can authenticate it — in v1 those fields rode entirely
outside the AEAD, which is the mechanism behind **TM-1**.

The AAD is **not JSON**. The two implementations must agree byte-for-byte, and
JSON offers too many ways to differ silently: key order, `null` versus omitted,
number formatting, unicode escaping, whitespace. Instead each field is written in
a fixed order as `<byte length>:<bytes>`, after the prefix `hqchat/v2/aad\n`:

```
t, sender, msgId, cid, n, pn, rk, kemCt, ctId, ctMt, ctOt, otId
```

Absent fields encode as `0:` — they occupy their position, so a header with a
one-time key cannot encode identically to one without. Lengths are in **bytes**,
not characters: a multi-byte `msgId` is the one case where a character count
would agree on ASCII and diverge everywhere else.

The field order and the encoding are **unchanged** by the move to client ids.
Only the value of `sender` shrank.

## 6. Security properties

**Holds:**

- *Confidentiality and integrity* against the server and the broker, which see
  only ciphertext and the sender's own public key.
- *Forward secrecy* against identity-key compromise, once the relevant prekey
  secret is gone. This is the property v1 did not have at all.
- *Post-compromise security*: a compromise heals on the next ratchet step,
  bounded by the step policy in §4.
- *Replay rejection*: a consumed index yields no key, and a retired chain cannot
  be re-entered (`seenChains`).
- *Header integrity*: a rewritten header produces no message rather than a wrong
  one.
- *Key–name binding*: a contact's identifier commits to their key, so a key that
  arrives from the server or from a peer is **checked** rather than trusted. A
  substituted key produces no session, not a wrong one — and, because the id is
  the key, a re-key is a new identity rather than a silent replacement.

**Does not hold:**

- *Authentication beyond TOFU.* Narrowed, not closed. What is trusted on faith is
  now the **id you were first given** — that this id is the person you mean.
  Everything downstream of that is arithmetic: no key that fails the commitment
  is ever pinned. The safety number is still what settles the first question, and
  it deliberately fingerprints raw **key bytes** rather than ids, because it
  verifies key material and not names.
- *Metadata privacy.* The broker sees who talks to whom and when. The topic is a
  blind hash, but membership is derivable by anyone holding both ids — and an id
  is derivable by anyone holding the corresponding public key.
- *Deniability.* Not a design goal.
- *Protection from a compromised endpoint.* Message history is at rest on the
  device under a separate key (see the threat model).

## 7. Constants

| Name | Value | Meaning |
|---|---|---|
| `MAX_SKIPPED` | 2000 | cached skipped message keys, across all chains |
| `RATCHET_MIN_STEP_INTERVAL` | 60 s | earliest a direction flip may step |
| `RATCHET_MAX_MESSAGES_PER_CHAIN` | 32 | forces a step regardless of time |
| `MAX_SEEN_CHAINS` | 64 | retired chains remembered for replay rejection |
| one-time prekey pool | 8 | published per client; replenished below 4 |
| medium-term lifetime | 7 days | rotation period |
| client id length | 64 hex | `SHA-256(hex(pk))`; pinned in `identity-vectors.json` |

The first three are in the vector file and asserted by both implementations. v1
carried its equivalents as a prose contract ("MUST stay equal to their Swift
twins") that no test checked.

## 8. What is deliberately absent

- **Media keys.** v1 derived a per-epoch `mediaKey` that no code ever used, while
  the only media paths that existed rode the static epoch-0 key. It is gone; when
  media lands it gets its own chain rather than a static per-epoch key.
- **A separate handshake frame.** `aes` and `key_rotate` are deleted. The
  handshake rides the first real message.
- **Migration.** Nothing had shipped. State at a different protocol version is
  deleted and the pair re-handshakes. The same applies to the identifier change:
  `sender` is a different value and the conversation topic is a different string,
  so both ends re-handshake regardless — which is why the client purges its
  ratchet material rather than trying to carry it across (`StoreMigration`).
- **An in-place re-key.** `pendingKeyHex` / `acceptKeyChange` modelled "the
  server says this contact's key changed; accept it?" That state cannot exist
  now — see §2.
