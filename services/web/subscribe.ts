import { IncomingMessage, ServerResponse } from "http";
import { StripeService } from "../stripe/api";

// Web subscription flow for the iOS "linking code" model (App Store policy
// forbids in-app Stripe checkout). The user gets their linking code — the
// blinded PK = SHA-256(public key) — from the app, opens this page, and is
// redirected to Stripe Checkout. On success the webhook flips their tier and
// the app picks it up on refresh.

const CODE_RE = /^[0-9a-f]{64}$/;

/** Escape user input before interpolating into HTML (prevents reflected XSS). */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

function baseUrl(req: IncomingMessage): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const host = req.headers.host || "localhost";
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  return `${proto}://${host}`;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function page(title: string, inner: string): string {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · DissQus</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:linear-gradient(160deg,#5b6cff 0%,#8b5cf6 100%); min-height:100vh;
         display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { background:#fff; color:#111; max-width:440px; width:100%; border-radius:20px;
          padding:32px; box-shadow:0 20px 60px rgba(0,0,0,.25); }
  h1 { font-size:1.5rem; margin:0 0 8px; }
  p { color:#555; line-height:1.5; }
  input { width:100%; padding:14px; font:inherit; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          border:1px solid #ddd; border-radius:12px; margin:12px 0; letter-spacing:.5px; }
  button { width:100%; padding:14px; font:inherit; font-weight:600; color:#fff;
           background:#5b6cff; border:0; border-radius:12px; cursor:pointer; }
  .logo { width:64px; height:64px; border-radius:18px; margin:0 auto 16px;
          background:linear-gradient(135deg,#5b6cff,#8b5cf6); display:flex; align-items:center;
          justify-content:center; font-size:30px; }
</style></head>
<body><div class="card"><div class="logo">✦</div>${inner}</div></body></html>`;
}

function formHtml(code = ""): string {
  return `<h1>Subscribe to DissQus</h1>
  <p>Enter the linking code shown on your app's subscription screen to connect your subscription to your account.</p>
  <form method="POST" action="/subscribe">
    <input name="code" placeholder="64-character linking code" value="${escapeHtml(code)}"
           autocomplete="off" autocapitalize="off" spellcheck="false" required>
    <button type="submit">Continue to payment</button>
  </form>`;
}

function send(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    // No scripts on this page; only inline styles. Lock it down.
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(body);
}

/** Handle any /subscribe* route. */
export async function handleSubscribe(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url || "/", "http://localhost");
  const path = url.pathname;

  if (path === "/subscribe/success") {
    return send(res, 200, page("Subscribed", `<h1>You're subscribed 🎉</h1>
      <p>Return to the DissQus app and tap <b>“I've already subscribed — Refresh”</b>.</p>`));
  }
  if (path === "/subscribe/cancel") {
    return send(res, 200, page("Cancelled", `<h1>Checkout cancelled</h1>
      <p>No charge was made. You can subscribe any time.</p>`));
  }

  // Linking code from query (?code=, e.g. the app's QR) or POSTed form.
  let code = url.searchParams.get("code") || "";
  if (req.method === "POST") {
    const body = await readBody(req);
    code = new URLSearchParams(body).get("code") || code;
  }
  code = code.trim().toLowerCase();

  if (!code) return send(res, 200, page("Subscribe", formHtml()));
  if (!CODE_RE.test(code)) {
    return send(res, 400, page("Subscribe",
      `<h1>That code looks off</h1><p>A linking code is 64 hex characters. Copy it from the app's subscription screen and try again.</p>` + formHtml(code)));
  }

  try {
    const result = await StripeService.createWebCheckout(code, baseUrl(req));
    if (result.active) {
      return send(res, 200, page("Already active", `<h1>Already subscribed 🎉</h1>
        <p>This code already has an active subscription. Go back to the app and refresh.</p>`));
    }
    res.writeHead(302, { Location: result.checkoutUrl! });
    res.end();
    return;
  } catch (e: any) {
    console.error("[subscribe] error:", e?.message || e);
    return send(res, 500, page("Error", `<h1>Something went wrong</h1>
      <p>Please try again in a moment.</p>`));
  }
}
