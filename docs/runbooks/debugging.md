# Debugging: "my message didn't arrive"

The most common report, and the one that used to take longest to answer because
the evidence lives in four places. This is the order to look in, and what each
answer means.

Every step is a real command. Run them from the VM unless it says otherwise.

## 0. Get the two public keys

Everything downstream is keyed on public keys, not usernames. From the app:
Settings → Account shows the local key fingerprint; the full hex is what you
need. Then:

```bash
HASH=$(node -e 'const c=require("crypto");const[a,b]=process.argv.slice(1).sort();console.log(c.createHash("sha256").update(a+b).digest("hex"))' "$PK_A" "$PK_B")
echo "conversation topic: c/$HASH"
```

## 1. Is the broker healthy at all?

```bash
curl -s 127.0.0.1:8092/health | jq          # broker-watch
```

`unhealthy: []` means EMQX, its authn hook, its Postgres ACL link and the
database itself are all up. A
non-empty list is your answer — go fix that first. If broker-watch itself is
down, from your laptop:

```bash
./infra/deploy/scripts/emqx-dashboard.sh --status
```

**`!! authz-pg status=disconnected`** means the topic ACL is not being enforced
or is denying everything — and with `deny_action = disconnect`, "denying
everything" means dropping every client that touches a topic. That is an incident, not a message problem — see
[emqx-acl.md](../architecture/emqx-acl.md).

## 2. Was the sender allowed to publish?

```bash
# $ID_A is the sender's CLIENT ID — sha256 of its lowercase-hex public key,
# 64 characters. `check-mqtt-acl.ts` takes a username, an id, or a full public
# key and works it out for you.
psql "$(cat /etc/hqcat/prod/secrets/database_url_direct)" \
  -c "SELECT topic, action FROM mqtt_acl WHERE id = '$ID_A'"
```

You are looking for a `c/$HASH` row with `action = all`. If it is missing, the friendship never
granted the topic (app-api writes it on accept) and **EMQX disconnected the
sender the moment it published** — `deny_action = disconnect`. The sender will
have seen a connection drop, not an error.

## 3. Did the message reach the broker?

In the EMQX dashboard (`emqx-dashboard.sh`), *Diagnose → WebSocket/Topic metrics*,
or subscribe as the privileged identity and watch:

```bash
docker compose -f infra/deploy/docker-compose.yml logs -f emqx | grep "$HASH"
```

- **Nothing at all** → it never left the sender. Look at the app (§6).
- **Published, not delivered** → the recipient was not subscribed. Check their ACL
  entry too: subscribing is authorized separately from publishing.

## 4. Was the recipient online, and did they get woken?

Presence is a retained MQTT value held by the broker, not a row — read it from
the broker rather than the database:

```bash
./infra/deploy/scripts/emqx-dashboard.sh          # then look up the client
```

Then ask the push side directly. Start here, not with the logs — it reports
every step of the path in one go, and it has to run in `push-bridge` because that
is the only service mounted the APNs key:

```bash
docker compose -f infra/deploy/docker-compose.yml exec push-bridge node --import tsx scripts/check-push.ts <username>
```

It answers three separate questions that all present as "my phone did not buzz":

1. **Is APNs configured at all?** The bridge prints the same verdict on every
   connect (`📨 APNs ready (…)` / `APNs is not configured — no device will be
   woken`). An incomplete config is escalated to Sentry at boot; neither state
   stops the service, because waking nobody is what both of them do and only one
   of them would also crash-loop the container. Missing `APNS_TOPIC_IOS` counts
   as incomplete —
   with a valid key and no topic, a push is built, addressed to nothing, and
   dropped without a word.
2. **Has the device ever registered?** No row in `push_tokens` means the OS never
   handed the app a token: permission denied, or a build with no `aps-environment`
   entitlement. The app re-registers on every auth success, so this is not stale.
3. **Did the bridge think they were reachable?** The bridge only wakes members it
   believes are **offline**, and it decides that once, when the message is
   published, with no retry. A device that is asleep but still marked online gets
   nothing — permanently, for that message.

```bash
docker compose -f infra/deploy/docker-compose.yml logs push-bridge | grep 'could not wake'
```

Each line names the reason (`no-config`, `no-topic-ios`, `rejected`, …), once per
account per reason.

For (3): the app publishes a retained `offline` from its scene-phase handler and
holds an iOS background assertion open until that frame has actually reached the
socket. If the device log shows `⚠️ could NOT announce offline` (Settings →
diagnostics), the socket was already gone and only the Last-Will will correct it
— which takes up to 45 seconds, and every message in that window is skipped.

## 5. Is it queued rather than lost?

QoS-1 messages for a disconnected client are held **in the MQTT session**, not in
the database. They replay when the client reconnects with the same `clientId` (= pk) and
`clean-session = false`. If the client reconnected with a *different* client id,
the session — and the backlog — is gone. That is worth checking before assuming
delivery failed.

## 6. On the device

Debug builds log the wire. `dlog` output shows envelope types and topics (never
payloads):

```
[ConversationRouter] ❌ no friend pinned for 04a1b2c3…
[ConversationRouter] ❌ no ratchet key for epoch 3
```

- **"no friend pinned"** → the message arrived and was discarded: the local store
  has no friend with that public key. Usually a directory sync that has not run.
- **"no ratchet key for epoch N"** → the two sides disagree about the ratchet.
  The peer rotated while this device was away and the epoch seed never landed.
- **Nothing logged at all** → the app is not subscribed. Check that login ran
  `refreshDirectory()` and that the conversation topic is in its desired set.

## 7. Sentry

Filter by `component` — `auth`, `api`, `push-bridge`, `broker-watch`, `bot`,
`server`. Every REST response carries `x-request-id`; the same id is on the log
line and the Sentry event, so if the user can quote it you can go straight to it.

## Quick table

| What you see | Where it is |
|---|---|
| Sender's connection drops when they send | ACL missing the topic (§2) |
| Message delivered to some devices only | per-device subscription or session (§3, §5) |
| Delivered late, in a burst, after opening the app | working as designed — session replay (§5) |
| No push while backgrounded, ever | APNs unconfigured — `check-push` (§4) |
| No push while backgrounded, sometimes | presence stuck "online" (§4) |
| Arrives but shows nothing in the conversation | decrypt failure — ratchet epoch (§6) |
