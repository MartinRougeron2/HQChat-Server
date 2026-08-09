// DB-2 guard (security audit 2026-08): `setUsername` must reject any username
// that could collide with / escape a Redis key namespace (`user:`, `friends:`,
// `username:`, `admission:exempt`, …). The charset check runs BEFORE any Redis
// command, so these cases throw synchronously and need no Redis server (the DB
// module uses ioredis `lazyConnect`, so importing it opens no socket).
//
// If someone ever loosens the `^[a-zA-Z0-9_]+$` rule in services/db/api.ts, this
// test fails — a crafted `":"`/whitespace/control-char username must never be
// accepted.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";

const PK = "a".repeat(64); // shape irrelevant — validation trips before any lookup

// Every one of these contains a character outside [A-Za-z0-9_] or violates the
// length bound, so the charset/length guard rejects it before touching Redis.
const REJECTED = [
  "evil:user", // ':' — the Redis key-namespace separator
  "user:friends:x", // multiple ':' segments
  "admission:exempt", // tries to name an internal key namespace
  "has space", // whitespace
  "tab\tuser", // control char
  "new\nline", // control char / injection
  "dash-name", // '-' not permitted
  "dot.name", // '.' not permitted
  "emoji😀", // non-ASCII
  "ab", // too short (< 3)
  "x".repeat(33), // too long (> 32)
  "", // empty
];

for (const name of REJECTED) {
  test(`setUsername rejects ${JSON.stringify(name)}`, async () => {
    await assert.rejects(
      () => DB.setUsername(PK, name),
      /between 3 and 32|letters, numbers, and underscores/,
      `expected ${JSON.stringify(name)} to be rejected by the charset/length guard`
    );
  });
}
