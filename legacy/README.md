# legacy — the retired `/ws` monolith

Nothing in this directory runs in production. It is here for exactly one reason:
`e2e.test.ts` and `account-delete.e2e.test.ts` are still the only end-to-end
coverage of the HQC-KEM handshake and the double ratchet **against a real running
server**, and deleting working coverage to tidy a directory is a bad trade.

## What is here

| File | Was |
|---|---|
| `server.ts` | the single-WebSocket server: auth, friend graph, presence, messages, calls, media — everything |
| `client.ts`, `test-clients.ts`, `stress.ts` | protocol clients + the load generator that drove it |
| `enums.ts` | the ~40 WS message types |
| `secure-transport.ts` | the per-connection AES layer the WS protocol needed for framing — TLS does this now |
| `e2e.test.ts`, `account-delete.e2e.test.ts`, `test-client.ts` | the end-to-end suite (needs Redis) |
| `secure-transport.test.ts` | unit tests for the above |

`authProof` — the one function the live handshake still uses — was split out to
[`lib/auth-proof.ts`](../lib/auth-proof.ts) and is NOT legacy.

## Running it

```bash
npm run test:e2e        # the reason this directory exists (needs Redis on :6379)
npm run legacy:server   # boots the monolith locally, if you need to reproduce something
```

## When this directory goes away

When the same paths have MQTT/REST end-to-end tests: connect through EMQX with a
real token, publish a `ConversationEnvelope`, assert the peer decrypts it, assert
the topic ACL refuses a stranger. That is a tracked follow-up. Once it exists,
delete this directory — do not port it.
