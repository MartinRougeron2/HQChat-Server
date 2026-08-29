# Authentication

How a client goes from "I hold a private key" to "I have a live MQTT session",
what it is allowed to do when it gets there, and what each component is trusted
with along the way.

Nothing here is a password. Identity is an HQC key pair generated on the device;
the server never sees the private half, and "logging in" means proving you can
decapsulate a ciphertext addressed to your public key.

## Two doors

There are two ways in, and they are separate endpoints rather than one endpoint
with a flag:

| | `/auth/free/*` | `/auth/paid/*` |
|---|---|---|
| Who gets in | anyone holding a key pair | only a key bound to a live subscription |
| Refused with | — | `402 NOT_CLAIMED`, **before** the KEM encapsulation |
| Session scope | `free` | `premium` |
| Can do | talk to the helper bot | everything, including adding contacts |

The paid door answers before doing any work: an unclaimed key costs one
primary-key lookup and never reaches the native HQC library. That is only safe to do because
the free door exists — refusing at the paid door denies nobody access to the
app, so it is a gate rather than a subscriber-status oracle bolted to the only
way in.

The entitlement is decided once, at the door, and **stored in the session**. No
later request re-derives it: `/friends/invite` reads one column, not the
subscription tables and certainly not Stripe.

There is no door-less `/auth/init`. It was one endpoint once; anything still
calling that path gets a 404, not a fallback.

### The helper bot uses the paid door

`bot/bot.ts` knocks on `/auth/paid/*`, which looks wrong — the bot pays nobody —
and is nonetheless the only door that works for it.

Admission is not the reason. The bot registers its own public key in
`admission_exempt` at startup, so `checkAdmission` waves it through either door.
The **scope** is the reason: the bot's job is accepting invites, and
`POST /friends/accept` refuses a `free` session with 402 `PREMIUM_REQUIRED`. On
the free door the bot would authenticate, report itself healthy, and silently
never accept an invite again. The paid door also re-runs
`regrantAllFriendTopics`, which is what restores the bot's conversation ACLs
after a restart.

So: exemption decides *whether* a caller gets in, the door decides *what it may
then do*, and a privileged non-paying client needs the paid door for the second
of those.

## The flow

These routes are the **only** place a public key enters the system: the server
has to encapsulate a challenge to it, which nothing else in the stack does.
Everything downstream — the session, the ACL, the topics, the broker's client id,
`/mqtt/authn`'s username — names the caller by its **client id**,
`id = sha256(lowercase-hex(pk))`. `/auth/*/verify` is where the two are tied
together, immediately after the KEM proof establishes that the caller holds the
key, and `users.identity_pk` written there is the only durable copy of an
account's key the server keeps (it is what `GET /peer/{id}/key` serves).

```mermaid
sequenceDiagram
    autonumber
    participant App as App<br/>(AuthService.swift)
    participant Auth as auth<br/>(auth/main.ts)
    participant PG as Postgres
    participant EMQX
    participant API as app-api<br/>(api/main.ts)

    Note over App,Auth: 1 — knock on the paid door first
    App->>Auth: POST /auth/paid/init { pk }
    Auth->>PG: subscription_claims → subscriptions.state
    alt not claimed
        Auth-->>App: 402 NOT_CLAIMED (no encapsulation performed)
        App->>Auth: POST /auth/free/init { pk }
    end

    Note over App,Auth: 2 — prove possession of the private key
    Auth->>Auth: HQC encapsulate to pk → (ct, ss)
    Auth->>PG: INSERT auth_challenges (proof = HKDF(ss,"auth"), 60s)
    Auth-->>App: { ct }
    App->>App: decapsulate(ct) → ss<br/>proof = HKDF(ss,"auth")
    App->>Auth: POST /auth/{door}/verify { pk, solution }
    Auth->>PG: DELETE … RETURNING proof  (single use — no replay)
    Auth->>Auth: constant-time compare

    Note over Auth: 3 — re-check admission after the proof
    Auth->>PG: checkAdmission(pk, door)
    Note right of Auth: a subscription can lapse inside<br/>the 60s challenge window

    Note over Auth,PG: 4 — mint credentials at the door's scope
    Auth->>Auth: id = sha256(hex(pk))
    Auth->>PG: INSERT users (id, identity_pk) — the only copy of the key
    Auth->>PG: INSERT sessions (sha256(token), id, iat, scope)
    Auth->>PG: INSERT mqtt_tokens (id, sha256(token))
    Auth->>PG: grantSelfTopics(id) · ensureBotFriendship(id)
    opt premium
        Auth->>PG: regrantAllFriendTopics(id)
    end
    Auth-->>App: { scope, sessionToken, mqttToken, mqttExpiresAt }

    Note over App,EMQX: 5 — connect
    App->>EMQX: CONNECT clientId=id, username=id, password=mqttToken
    EMQX->>Auth: POST /mqtt/authn { username, password, clientid }
    Auth->>PG: verify sha256(token) against mqtt_tokens
    Auth-->>EMQX: { result: "allow", expire_at }
    EMQX-->>App: CONNACK

    Note over App,API: everything else is REST with the session bearer
    App->>API: GET /friends, POST /username, …
    App->>API: POST /friends/invite
    API->>API: session.scope === "premium"?  else 402 PREMIUM_REQUIRED
```

## Claiming a subscription

A subscription is bought on the website and claimed from the app. The two have
nothing in common — one is a Stripe customer, the other an HQC key pair — so an
email address bridges them, and a code sent to it is the only proof accepted
that the person holding the device is the person who paid.

```mermaid
sequenceDiagram
    autonumber
    participant Web as Website<br/>(/subscribe)
    participant Stripe
    participant API as app-api<br/>(webhook)
    participant PG as Postgres
    participant Auth as auth<br/>(/claim/*)
    participant Mail as Resend
    participant App

    Web->>Stripe: Checkout (Stripe collects the email)
    Stripe->>API: checkout.session.completed
    API->>API: H = sha256(lowercased email)
    API->>PG: subscriptions(H) = active · subscription_customers(cus_…) = H
    API->>Mail: "open the app and enter this address"
    Note over API: the plaintext address is used here and discarded

    App->>Auth: POST /claim/start { email }
    Auth->>PG: subscriptions(H) — active?
    Auth->>PG: otp(H) = sha256(code + OTP_PEPPER), expires in 10m
    Auth->>Mail: 6-digit code
    Auth-->>App: 200 { ok: true }
    Note right of Auth: identical whether or not that<br/>address bought anything

    App->>Auth: POST /claim/verify { email, code, pk }
    Auth->>PG: INSERT subscription_claims (id, H) — under the device cap
    App->>App: sign in again — the paid door now admits this key
```

**The server never stores an email address.** Everything is keyed by
`H = sha256(lowercased, trimmed email)`, so a dump of this database says which
subscriptions exist but not whose. Stripe remains the only system holding the
plaintext.

**`OTP_PEPPER` is why the stored hash is worth anything.** A six-digit code has
a million preimages; without a server-side secret in the hash, anyone reading a
database dump inverts every pending code with a for-loop.

### The test account

One address short-circuits all of the above: `TEST_ACCOUNT_EMAIL`
(`test@test.test` by default) links **any number of devices** with the fixed code
`TEST_ACCOUNT_CODE` (`000000`), with no purchase behind it and no mail sent — the
address is not deliverable and the code never changes. It exists because the
claim screen is otherwise untestable without a card: App Review cannot buy a
subscription, and a fresh preprod stack has no Stripe data in it.

It lives alone in `services/subscription/test-account.ts` and touches the rest of
the flow in exactly two places (`startClaim`, `verifyClaim`). The paid door knows
nothing about it: the branch writes a real `subscriptions` row, so `isClaimed()`
finds an active subscription the same way it would for a buyer.

This is a **deliberate hole**, and both halves of it are in the public tree. What
it grants is the premium *scope* and nothing more — every device still holds its
own keypair and its own conversations — so the cost is a subscription that was
not paid for, not a route into anyone's messages. Two things keep it honest:
every boot with it enabled prints a config warning, and every new device that
links this way mails `TEST_ACCOUNT_ALERT_TO`.

Closing it is `TEST_ACCOUNT_EMAIL=` (empty) plus a restart. That stops new links
only — a device bound earlier holds an ordinary claim row by then, and revoking
it means cancelling the subscription and deleting the claims (the alert mail
carries both statements).

## Why it is shaped like this

**Two tokens, two jobs.** The MQTT token (12 h) is the credential that travels as
an MQTT password; the REST session bearer is what lets a client rotate it
*without* touching the private key, which is why a dropped connection does not
cost the user a biometric prompt.

**The MQTT token used to be 5 minutes, and that was a revocation mechanism in
disguise.** With no way to end a live session, the only bound on a revoked client
was how long its token had left — so every client was disconnected and rebuilt
twelve times an hour to keep that bound short (LAT-1). Revocation now acts
directly ([`lib/emqx.ts`](../../services/server/lib/emqx.ts) drops a subscription
or kicks a session), so the TTL means what a credential lifetime should mean: how
long a *stolen* token stays useful.

**The session slides.** Fixed at an hour, it cost a prompt every hour of active
use — the refresh 401'd and the client fell back to a full handshake. Each use now
extends the idle window, with a 30-day absolute cap so a stolen bearer in
continuous use cannot live forever.

**Scope in the session needs revocation that acts.** A `premium` bearer would
otherwise outlive a cancelled subscription by up to its 30-day cap, which is not
a refund policy. `sessions.id` indexes live bearers so the cancellation webhook
can end them, alongside `EMQX.kick` and the friend-topic revocation.

**A lapse revokes topics but never deletes anything.** Friendships and message
history survive; `regrantAllFriendTopics` puts the ACL back on the next paid
login. The free door deliberately does *not* revoke — a client that landed there
because a database read blipped would otherwise tear down every conversation it
has.

**Expiry is enforced by the broker, not by politeness.** `/mqtt/authn` hands EMQX
the token's `expire_at`, and EMQX disconnects the client when it lapses.

**The challenge is consumed atomically** (`GETDEL`), so a captured
`/auth/*/verify` cannot be replayed. There is an optional per-CONNECT nonce on
top for the MQTT leg.

## Components

| Component | Trusted with | Not trusted with |
|---|---|---|
| `AuthService.swift` | the private key, in the Keychain behind biometrics | — |
| `auth/main.ts` | minting scoped tokens, admission, mailing claim codes | reading messages (it never sees one), talking to Stripe |
| `api/main.ts` | the friend graph, the Stripe webhook, the paywall | anything about a session it did not resolve |
| Postgres | token *hashes*, the challenge, the ACL, claim state | plaintext tokens, private keys, email addresses |
| Stripe | the customer's email and card | the crypto identity — no public key is ever sent |
| EMQX | enforcing authn/authz per packet | decrypting payloads |

## Failure modes worth recognising

| Symptom | Usually means |
|---|---|
| `/auth/paid/init` returns 402 `NOT_CLAIMED` | no live subscription for this key — the client falls back to the free door, which is a normal signed-in state |
| `/auth/*/init` returns 403 `NOT_ADMITTED` | an allowlist server that does not want this key. Retrying the other door asks the same question |
| `/friends/invite` returns 402 `PREMIUM_REQUIRED` | a free session. The user must claim a subscription, then sign in again |
| The subscribe button 302s and the browser does nothing | the page's CSP `form-action` does not permit the redirect target. It is enforced across redirects, so a cross-origin 302 out of a form POST needs the destination listed — see `CHECKOUT_ORIGIN` in `services/web/subscribe.ts`. The server log looks perfectly healthy |
| The app reports "Couldn't reach the server (404)" on a claim | the client built the URL from the `/auth` prefix. `/claim/*` is served BY the auth service but mounted at the ROOT by nginx, so `/auth/claim/start` is a 404. `ServerConfig.claimBaseURL` is the origin for exactly this reason |
| `/claim/start` returns 200 but no code arrives | either that address bought nothing, or mail is failing. The response cannot tell you which — check the server log, which can |
| `/claim/verify` returns `NO_CODE` after wrong guesses | the code was burned at 5 attempts. Request a new one |
| CONNACK returns code 5 (not authorised) | the MQTT token expired or was already consumed — refresh and reconnect |
| `/auth/verify` returns 401 | the challenge expired (60 s) or the device holds the wrong key for that identity |
| `/auth/refresh` returns 401 | the session lapsed — a full handshake is needed, and the user sees a prompt |
| `/auth/init` returns 404, on repeat, from a service | that caller predates the two-door split and was never moved. There is no un-doored init path; pick `/auth/free/*` or `/auth/paid/*` by the scope the caller needs |
| A service authenticates fine, then 402s on every write | it authenticated through the free door but needs `premium`. The door, not the admission exemption, is what to change |
| Premium user suddenly cannot message friends | the subscription lapsed and the webhook revoked the topics. Resubscribing restores them on the next paid login |
