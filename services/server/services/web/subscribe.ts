import { logger } from "../../lib/logger";
import { IncomingMessage, ServerResponse } from "http";
import { StripeService } from "../stripe/api";
import { DEVICE_CAP } from "../subscription/api";

// The website's checkout surface, and the only place anything is sold.
//
// It used to ask for a 64-character "linking code" — the blinded public key,
// copied out of the app — so the payment could be bound to a device at checkout
// time. Nothing is bound here now: Stripe collects an email address, and the
// app claims the subscription afterwards with a code sent to it
// (services/subscription/api.ts). One field the user already knows, instead of
// a hex string they have to carry between two devices before they can pay.

function baseUrl(req: IncomingMessage): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const host = req.headers.host || "localhost";
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  return `${proto}://${host}`;
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
  ol { color:#555; line-height:1.6; padding-left:20px; }
  button { width:100%; padding:14px; font:inherit; font-weight:600; color:#fff;
           background:#5b6cff; border:0; border-radius:12px; cursor:pointer; margin-top:20px; }
  .logo { width:64px; height:64px; border-radius:18px; margin:0 auto 16px;
          background:linear-gradient(135deg,#5b6cff,#8b5cf6); display:flex; align-items:center;
          justify-content:center; font-size:30px; }
</style></head>
<body><div class="card"><div class="logo">✦</div>${inner}</div></body></html>`;
}

/**
 * Where Stripe Checkout is served from, and therefore where the POST below
 * redirects the browser.
 *
 * This is in the CSP, and it has to be. `form-action` is enforced across
 * REDIRECTS, not just on the initial submission target: with `form-action
 * 'self'` the browser blocks the 302 out to Stripe, and blocks it *silently* —
 * the server logs a clean 302, the page simply does not move, and the only
 * evidence is a console line the user never sees. That is what "no error, just
 * nothing" looked like.
 *
 * If Stripe Checkout is ever moved to a custom domain, this constant moves with
 * it, or the button goes dead again in exactly the same invisible way.
 */
export const CHECKOUT_ORIGIN = "https://checkout.stripe.com";

/**
 * No scripts on these pages; only inline styles. Locked down apart from the one
 * hole the flow genuinely needs — see `CHECKOUT_ORIGIN`.
 */
export const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  `form-action 'self' ${CHECKOUT_ORIGIN}`,
  "base-uri 'none'",
].join("; ");

function send(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(body);
}

/** Handle any /subscribe* route. */
export async function handleSubscribe(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = new URL(req.url || "/", "http://localhost").pathname;

  if (path === "/subscribe/success") {
    return send(res, 200, page("Subscribed", `<h1>You're subscribed 🎉</h1>
      <p>Check your inbox — we've sent the address to use.</p>
      <ol>
        <li>Open DissQus on your device.</li>
        <li>Choose <b>Restore with your email</b>.</li>
        <li>Enter the email you just paid with, then the 6-digit code we send you.</li>
      </ol>
      <p>You can link up to ${DEVICE_CAP} devices this way.</p>`));
  }
  if (path === "/subscribe/cancel") {
    return send(res, 200, page("Cancelled", `<h1>Checkout cancelled</h1>
      <p>No charge was made. You can subscribe any time.</p>`));
  }

  // GET shows the offer; POST starts checkout. Splitting them keeps the
  // redirect off a route a crawler or a link preview might follow.
  if (req.method !== "POST") {
    return send(res, 200, page("Subscribe", `<h1>Subscribe to DissQus</h1>
      <p>Unlock contacts and private conversations. Post-quantum end-to-end
         encryption on every message, on every device you link.</p>
      <form method="POST" action="/subscribe">
        <button type="submit">Continue to payment</button>
      </form>`));
  }

  try {
    const checkoutUrl = await StripeService.createCheckout(baseUrl(req));
    // Say so if Stripe ever hands back a host the page's CSP will not let the
    // browser follow. Without this the redirect is issued, the browser drops it
    // on the floor, and the server log shows a perfectly healthy 302 — the exact
    // failure that made this bug invisible the first time.
    if (!checkoutUrl.startsWith(`${CHECKOUT_ORIGIN}/`)) {
      logger.error(
        `[subscribe] checkout URL origin is not ${CHECKOUT_ORIGIN} — the CSP form-action ` +
        `will block this redirect and the button will do nothing. Got: ${new URL(checkoutUrl).origin}`
      );
    }
    res.writeHead(302, { Location: checkoutUrl });
    res.end();
  } catch (e: any) {
    logger.error("[subscribe] error:", e?.message || e);
    return send(res, 500, page("Error", `<h1>Something went wrong</h1>
      <p>Please try again in a moment.</p>`));
  }
}
