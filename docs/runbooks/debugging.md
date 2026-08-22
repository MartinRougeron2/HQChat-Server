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
psql "$(cat /etc/hqcat/prod/secrets/database_url_direct)" \
  -c "SELECT topic, action FROM mqtt_acl WHERE pk = '$PK_A'"
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

Also check the push side:

```bash
docker compose -f infra/deploy/docker-compose.yml logs push-bridge | tail -50
```

The bridge only wakes members it believes are **offline**. The classic failure is
a device that is asleep but still marked online — the app publishes `offline` on
background precisely to avoid that, so if you see "online" for a backgrounded
device, that publish did not make it out.

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
| No push while backgrounded | presence stuck "online" (§4) |
| Arrives but shows nothing in the conversation | decrypt failure — ratchet epoch (§6) |
