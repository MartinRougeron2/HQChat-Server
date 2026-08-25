// The website's one buy button, checked without spending a Stripe API call.
//
// This file exists because of a bug that a live call was the only way to find:
// the session carried `customer_creation: 'always'`, which Stripe accepts only
// in payment mode. In subscription mode it is a 400, so every click of the
// only place this product is sold died at the API and rendered "Something went
// wrong". The parameters are exported now precisely so that class of mistake —
// a field that is valid Stripe, and valid TypeScript, but not valid for THIS
// mode — is caught here instead of in production.

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkoutSessionParams } from "../services/stripe/api";
import { CSP, CHECKOUT_ORIGIN } from "../services/web/subscribe";

const BASE = "https://chat.example.com";

test("checkout is a subscription, and the redirects come back to us", () => {
  const p = checkoutSessionParams(BASE);
  assert.equal(p.mode, "subscription");
  assert.equal(p.success_url, `${BASE}/subscribe/success`);
  assert.equal(p.cancel_url, `${BASE}/subscribe/cancel`);
  const items = p.line_items ?? [];
  assert.equal(items.length, 1);
  const item = items[0];
  assert.ok(item, "one line item");
  assert.equal(item.quantity, 1);
  assert.ok(item.price, "a price id, or there is nothing to buy");
});

test("no payment-mode-only parameter rides along on a subscription", () => {
  // Exactly the fields the pinned SDK's own type docs scope to another mode
  // (types/Checkout/SessionsResource.d.ts) — not a guess at which ones feel
  // payment-ish. `customer_creation` ("Can only be set in `payment` and `setup`
  // mode") is the one that actually shipped and took checkout down; the other
  // two carry the same restriction and would fail the same way.
  const paymentModeOnly = [
    "customer_creation",
    "payment_intent_data",
    "submit_type",
  ];
  const p = checkoutSessionParams(BASE) as Record<string, unknown>;
  for (const key of paymentModeOnly) {
    assert.ok(
      !(key in p),
      `${key} is only valid in payment mode — Stripe 400s the subscription checkout`
    );
  }
});

// The second half of the same outage. With the Stripe 400 fixed the server
// started issuing a clean 302 to checkout.stripe.com — and the browser threw it
// away, because `form-action` is enforced across REDIRECTS and the page said
// `'self'`. Nothing surfaced: a healthy 302 in the log, a page that did not
// move, and one console line nobody was looking at.

test("the page's CSP lets the browser follow the redirect to Stripe", () => {
  const formAction = CSP.split(";").map((d) => d.trim())
    .find((d) => d.startsWith("form-action"));
  assert.ok(formAction, "form-action must be stated, not left to default-src");
  assert.match(
    formAction,
    new RegExp(CHECKOUT_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    "form-action must permit the checkout origin or the POST redirect is silently dropped"
  );
});

test("widening form-action did not loosen anything else", () => {
  assert.match(CSP, /default-src 'none'/);
  assert.match(CSP, /base-uri 'none'/);
  assert.doesNotMatch(CSP, /script-src/, "these pages run no scripts");
  assert.doesNotMatch(CSP, /unsafe-eval/);
  // 'unsafe-inline' is for styles only — the pages are inline-styled by design.
  assert.match(CSP, /style-src 'unsafe-inline'/);
});

// Comp prices: annual, charged nothing, handed out from the Stripe dashboard to
// testers and friends. They entitle exactly what a paid subscription entitles —
// the app asks "is this key on a live subscription", never "which plan".

import { ENTITLING_PRICE_IDS, subscriptionIsEntitling, subscriptionPriceIds } from "../services/stripe/api";

const COMP = "price_1U7fxUKdAg16VdMqBEpDM2Aa";

/** The shape a `customer.subscription.*` payload has, trimmed to what we read. */
function subscription(...priceIds: string[]) {
  return { items: { data: priceIds.map((id) => ({ price: { id } })) } };
}

test("both the paid price and the comp price entitle", () => {
  const paid = checkoutSessionParams(BASE).line_items?.[0]?.price;
  assert.ok(typeof paid === "string" && paid, "the checkout price is a plain id");
  assert.ok(ENTITLING_PRICE_IDS.includes(paid), "what we sell must entitle");
  assert.ok(ENTITLING_PRICE_IDS.includes(COMP), "so must the comp plan");
});

test("the website never sells the comp price", () => {
  // The entire access control on the free plan is that no code path puts it in
  // a cart. If this ever fails, anyone can grant themselves a subscription.
  const params = checkoutSessionParams(BASE);
  const priced = (params.line_items ?? []).map((i) => i.price);
  assert.ok(!priced.includes(COMP), "checkout must be hard-wired to the paid price");
  assert.equal(priced.length, 1);
});

test("an unrelated price entitles nothing", () => {
  assert.equal(subscriptionIsEntitling(subscription("price_somethingelse")), false);
  assert.equal(subscriptionIsEntitling(subscription()), false, "no line items");
  assert.equal(subscriptionIsEntitling({}), false, "malformed payload");
  assert.equal(subscriptionIsEntitling(subscription(COMP)), true);
});

test("a mixed subscription entitles if ANY line entitles", () => {
  assert.equal(subscriptionIsEntitling(subscription("price_other", COMP)), true);
});

test("price ids are read from `plan` too, for older payload shapes", () => {
  assert.deepEqual(subscriptionPriceIds({ items: { data: [{ plan: { id: COMP } }] } }), [COMP]);
});
