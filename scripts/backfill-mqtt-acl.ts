// One-time migration: derive the MQTT topic ACL (`mqtt_acl:{pk}`) from the
// existing friend graph (`friends:{pk}`). Run ONCE on the VM before cutting
// clients over to MQTT (see deploy/EXTRACTION_PLAN.md, Phase 0):
//
//   docker compose run --rm app-api node --import tsx scripts/backfill-mqtt-acl.ts
//
// Idempotent — grantFriendTopic writes both sides and can be re-run safely.

// Must be first: loads .env + resolves *_FILE secrets so REDIS_URL is assembled.
import "../lib/config";
import { logger } from "../lib/logger";
import Redis from "ioredis";
import { DB } from "../services/db/api";

async function main() {
  const redis = new Redis(process.env.REDIS_URL || "redis://127.0.0.1:6379");
  let cursor = "0";
  let scannedKeys = 0;
  let grants = 0;
  const seenPairs = new Set<string>();

  logger.startup("[backfill-mqtt-acl] scanning friends:* …");
  do {
    const [next, keys] = await redis.scan(cursor, "MATCH", "friends:*", "COUNT", 200);
    cursor = next;
    for (const key of keys) {
      scannedKeys++;
      const pk = key.slice("friends:".length);
      const friends = await redis.smembers(key);
      for (const friendPk of friends) {
        // Deduplicate the symmetric edge so each friendship is granted once.
        const pair = [pk, friendPk].sort().join("|");
        if (seenPairs.has(pair)) continue;
        seenPairs.add(pair);
        await DB.grantFriendTopic(pk, friendPk);
        grants++;
      }
    }
  } while (cursor !== "0");

  logger.startup(
    `[backfill-mqtt-acl] done — ${scannedKeys} friend-sets scanned, ${grants} conversation topics granted.`
  );
  redis.disconnect();
  DB.disconnect();
}

main().catch((e) => {
  logger.error(`[backfill-mqtt-acl] failed: ${(e as Error).message}`);
  process.exit(1);
});
