// Rebuild the MQTT topic ACL from the friend graph.
//
//   docker compose run --rm app-api node --import tsx scripts/rebuild-mqtt-acl.ts
//
// `mqtt_acl` is materialised rather than a view over `friendships`, because EMQX
// queries it directly and a view would join on every authz cache miss. The cost
// of materialising is that it can drift — a grant that failed halfway, a row
// deleted by hand. This is the repair: `friendships` is the source of truth, so
// derive the whole table from it and let ON CONFLICT settle the difference.
//
// Idempotent by construction. It ADDS what is missing and does not remove
// anything, so running it can only widen access — pass --prune to also drop
// conversation grants that no friendship justifies.
//
// (This was `backfill-mqtt-acl.ts`, a one-time Redis SCAN written for the MQTT
// cutover. The derivation it performed is a single statement now.)

// Must be first: loads .env + resolves *_FILE secrets so DATABASE_URL is set.
import "../lib/config";
import { logger } from "../lib/logger";
import { q, disconnect } from "../services/db/pg";

async function main() {
  const prune = process.argv.includes("--prune");

  // Both members of every friendship get: `all` on the shared conversation
  // topic, and `subscribe` on the other's presence.
  const granted = await q(
    `WITH grants AS (
       SELECT pk_lo AS pk, 'c/' || hash AS topic, 'all' AS action FROM friendships
       UNION ALL
       SELECT pk_hi,       'c/' || hash,          'all'            FROM friendships
       UNION ALL
       SELECT pk_lo, 'u/' || pk_hi || '/presence', 'subscribe'     FROM friendships
       UNION ALL
       SELECT pk_hi, 'u/' || pk_lo || '/presence', 'subscribe'     FROM friendships
     )
     INSERT INTO mqtt_acl (pk, topic, action)
     SELECT pk, topic, action FROM grants
     ON CONFLICT (pk, topic) DO UPDATE SET action = EXCLUDED.action
     RETURNING pk`
  );

  // Everyone keeps their own topics: publish on their presence, all on their
  // inbox. Derived from `users` rather than from friendships, so an account with
  // no friends still has somewhere to be woken.
  const selfGranted = await q(
    `INSERT INTO mqtt_acl (pk, topic, action)
     SELECT pk, 'u/' || pk || '/presence', 'publish' FROM users
     UNION ALL
     SELECT pk, 'u/' || pk || '/inbox', 'all' FROM users
     ON CONFLICT (pk, topic) DO UPDATE SET action = EXCLUDED.action
     RETURNING pk`
  );

  logger.startup(
    `[rebuild-mqtt-acl] ${granted.rowCount} friendship grants, ${selfGranted.rowCount} self grants written`
  );

  if (prune) {
    // A conversation grant whose friendship is gone. Deliberately opt-in: this
    // is the only destructive thing here, and a bug in the WHERE clause would
    // silently cut people off from conversations that are perfectly valid.
    const pruned = await q(
      `DELETE FROM mqtt_acl a
        WHERE a.topic LIKE 'c/%'
          AND NOT EXISTS (
            SELECT 1 FROM friendships f
             WHERE 'c/' || f.hash = a.topic
               AND (f.pk_lo = a.pk OR f.pk_hi = a.pk)
          )`
    );
    logger.startup(`[rebuild-mqtt-acl] pruned ${pruned.rowCount} orphaned conversation grants`);
  }

  await disconnect();
}

main().catch((e) => {
  logger.error(`[rebuild-mqtt-acl] failed: ${(e as Error).message}`);
  process.exit(1);
});
