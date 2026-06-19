import * as http2 from "http2";
import * as crypto from "crypto";
import { DB } from "../db/api";

/**
 * Minimal APNs (token-based) push sender using Node built-ins — no node-apn
 * dependency. Sends an alert push to a user's registered device.
 *
 * Configure via env (see deploy/.env.example):
 *   APNS_KEY_ID, APNS_TEAM_ID, APNS_KEY_P8 (the .p8 contents, \n-escaped),
 *   APNS_TOPIC_IOS, APNS_TOPIC_MACOS, APNS_ENV (sandbox|production)
 *
 * If the env isn't set, send() is a no-op so the rest of the server is
 * unaffected — push simply stays dormant until you add the key.
 */

let cachedJwt: { token: string; iat: number } | null = null;

function getJwt(): string {
  const now = Math.floor(Date.now() / 1000);
  // APNs accepts a provider token for up to 1h; refresh well before that.
  if (cachedJwt && now - cachedJwt.iat < 3000) return cachedJwt.token;

  const b64 = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = { alg: "ES256", kid: process.env.APNS_KEY_ID };
  const payload = { iss: process.env.APNS_TEAM_ID, iat: now };
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const key = (process.env.APNS_KEY_P8 || "").replace(/\\n/g, "\n");
  const sig = crypto
    .sign("SHA256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
    .toString("base64url");

  const token = `${signingInput}.${sig}`;
  cachedJwt = { token, iat: now };
  return token;
}

export const ApnsService = {
  enabled(): boolean {
    return !!(
      process.env.APNS_KEY_ID &&
      process.env.APNS_TEAM_ID &&
      process.env.APNS_KEY_P8
    );
  },

  /** Fire-and-forget alert push to the user's registered device. */
  async send(pk: string, title: string, body: string): Promise<void> {
    try {
      if (!this.enabled()) return;
      const info = await DB.getPushToken(pk);
      if (!info) return;

      const topic =
        info.platform === "macos"
          ? process.env.APNS_TOPIC_MACOS
          : process.env.APNS_TOPIC_IOS;
      if (!topic) return;

      const host =
        process.env.APNS_ENV === "production"
          ? "api.push.apple.com"
          : "api.sandbox.push.apple.com";

      const client = http2.connect(`https://${host}`);
      client.on("error", (e) => console.error("[apns] connection error", e));

      const body_ = JSON.stringify({ aps: { alert: { title, body }, sound: "default" } });
      const req = client.request({
        ":method": "POST",
        ":path": `/3/device/${info.token}`,
        authorization: `bearer ${getJwt()}`,
        "apns-topic": topic,
        "apns-push-type": "alert",
        "content-type": "application/json",
      });

      let status = 0;
      let data = "";
      req.setEncoding("utf8");
      req.on("response", (h) => { status = Number(h[":status"]); });
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        if (status !== 200) console.error(`[apns] ${status} ${data}`);
        client.close();
      });
      req.on("error", (e) => { console.error("[apns] request error", e); client.close(); });
      req.write(body_);
      req.end();
    } catch (e) {
      console.error("[apns] send failed", e);
    }
  },
};
