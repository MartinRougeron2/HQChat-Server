// Push-bridge entrypoint (Phase 2 — see deploy/EXTRACTION_PLAN.md).
//
// Subscribes to every conversation topic and fires a CONTENT-FREE APNs wake to
// any conversation member who is currently offline. It sees ciphertext +
// metadata only — never plaintext.
//
// Presence is learned purely over MQTT (no EMQX API key needed): clients publish
// a RETAINED `u/{pk}/presence` = {"s":"online"} on connect and set an LWT
// {"s":"offline"} so a drop flips them offline. The bridge tracks this in-memory
// from the `u/+/presence` wildcard (each replica sees all presence). The message
// subscription is SHARED (`$share/…`) so replicas split the fan-in.
//
// It authenticates to EMQX with the privileged internal credential, which the
// auth server's /mqtt/authn grants superuser (bypassing the per-topic ACL).

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
initObservability("push-bridge");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import mqtt from "mqtt";
import { DB } from "../services/db/api";
import { ApnsService } from "../services/apns/api";

const PORT = Number(process.env.PORT || 8080);
const EMQX_URL = process.env.EMQX_URL || "ws://emqx:8083/mqtt";
const INTERNAL_MQTT_USER = process.env.INTERNAL_MQTT_USER || "svc-internal";
const INTERNAL_MQTT_SECRET = process.env.INTERNAL_MQTT_SECRET || "";
const SHARE_GROUP = process.env.PUSH_SHARE_GROUP || "pushbridge";

// In-memory presence, kept current from retained/LWT `u/{pk}/presence` messages.
const online = new Set<string>();

// --- Health endpoint (compose healthcheck) ---------------------------------
http
  .createServer((req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ok: true, service: "push-bridge", online: online.size }));
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  })
  .listen(PORT, () => logger.startup(`📨 push-bridge health on :${PORT}`));

// Event-loop / memory / query-latency early warning → Sentry. A stalled bridge
// silently stops waking offline devices, so it needs the same watch as the relay.
healthMonitor.start();

// --- MQTT ------------------------------------------------------------------
if (!INTERNAL_MQTT_SECRET) {
  logger.error("[push-bridge] INTERNAL_MQTT_SECRET unset — cannot authenticate to EMQX");
}

const client = mqtt.connect(EMQX_URL, {
  clientId: `pushbridge-${Math.random().toString(16).slice(2, 10)}`,
  username: INTERNAL_MQTT_USER,
  password: INTERNAL_MQTT_SECRET,
  clean: true,
  reconnectPeriod: 5000,
  keepalive: 30,
});

client.on("connect", () => {
  logger.startup(`📨 push-bridge connected to EMQX at ${EMQX_URL}`);
  // Presence: every user (unshared so this replica sees all of them).
  client.subscribe("u/+/presence", { qos: 0 });
  // Conversation fan-in: SHARED so replicas split the load; QoS1 for reliability.
  client.subscribe(`$share/${SHARE_GROUP}/c/+`, { qos: 1 });
});

client.on("error", (e) => logger.error(`[push-bridge] mqtt: ${e.message}`));
client.on("reconnect", () => logger.warn("[push-bridge] reconnecting to EMQX…"));

client.on("message", async (topic, payload) => {
  try {
    // Presence update: u/{pk}/presence
    const pres = topic.match(/^u\/([^/]+)\/presence$/);
    if (pres && pres[1]) {
      const pk = pres[1];
      const s = payloadState(payload);
      if (s === "online") online.add(pk);
      else online.delete(pk); // "offline" or a cleared retained message
      return;
    }

    // Conversation message: c/{hash} → wake offline members.
    const convo = topic.match(/^c\/([0-9a-f]+)$/);
    if (convo && convo[1]) {
      const hash = convo[1];
      const members = await DB.getHashMembers(hash);
      for (const pk of members) {
        if (online.has(pk)) continue; // sender is online; recipients online skip
        // Content-free wake — the payload is ciphertext and never inspected.
        ApnsService.send(pk, "New message", "You have a new message");
      }
    }
  } catch (e) {
    logger.error(`[push-bridge] handling ${topic}: ${(e as Error).message}`);
  }
});

/** Parse a presence payload → "online" | "offline". Empty/cleared retained = offline. */
function payloadState(payload: Buffer): "online" | "offline" {
  const raw = payload.toString("utf8").trim();
  if (!raw) return "offline";
  try {
    const j = JSON.parse(raw);
    return j?.s === "online" ? "online" : "offline";
  } catch {
    return raw === "online" ? "online" : "offline";
  }
}
