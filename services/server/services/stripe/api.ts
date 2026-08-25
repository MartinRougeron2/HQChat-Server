// Stripe — the only place money is handled, and the only system that holds a
// customer's email address in the clear.
//
// Checkout is NOT bound to a public key. It cannot be: the purchase happens on
// the website, in a browser, with no device identity anywhere near it. Stripe
// collects an address, the webhook hashes it, and the app claims the
// subscription later with a code sent to that address (services/subscription).
//
// The previous shape bound a checkout session to a blinded pk carried from the
// app as a 64-character "linking code". That made every purchase require the
// user to move a hex string between two devices before paying, and it made
// admission a live Stripe API call on every login.

import { logger } from '../../lib/logger';
import Stripe from 'stripe';

// Lazily constructed so a self-hosted server with ADMISSION_POLICY != stripe can
// boot WITHOUT a Stripe key. Throws a clear error only if Stripe is actually used.
let _stripe: Stripe | null = null;
function stripeClient(): Stripe {
  if (_stripe) return _stripe;
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is required for ADMISSION_POLICY=stripe / the Stripe webhook");
  }
  _stripe = new Stripe(key, { apiVersion: '2025-02-24.acacia' });
  return _stripe;
}

/** What the website sells. The ONLY price `createCheckout` ever puts in a cart. */
const PRICE_ID = process.env.STRIPE_PRICE_ID || 'price_1TjySfKdAg16VdMqoBBdqisu';

/**
 * Complimentary prices — annual, charged nothing, for testers and friends.
 *
 * Deliberately NOT on the website. There is no button, no link and no code that
 * puts one of these in a checkout; the only way to get one is for an operator to
 * hand it out from the Stripe dashboard. That is the whole access control, and
 * it is enough precisely because `createCheckout` above is hard-wired to
 * `PRICE_ID` — a visitor cannot ask for a different price than the one we build.
 *
 * Comma-separated, so another comp tier is a config change rather than a deploy.
 */
const COMP_PRICE_IDS = (process.env.STRIPE_COMP_PRICE_IDS || 'price_1U7fxUKdAg16VdMqBEpDM2Aa')
  .split(',').map((s) => s.trim()).filter(Boolean);

/**
 * Every price that entitles its holder to premium. Paid and comp are identical
 * downstream: the app asks "is this key on a live subscription", never "which
 * plan", so a comp subscriber is a premium subscriber in every respect.
 *
 * This list exists because access is granted from raw Stripe subscription
 * events (see `subscriptionIsEntitling`). Without it ANY subscription object in
 * the account — a different product, a leftover test — would grant premium.
 */
export const ENTITLING_PRICE_IDS: readonly string[] = [PRICE_ID, ...COMP_PRICE_IDS];

/** The price ids on a `customer.subscription.*` payload's line items. */
export function subscriptionPriceIds(sub: any): string[] {
  const items = (sub?.items?.data ?? []) as Array<any>;
  return items
    .map((i) => (typeof i?.price?.id === 'string' ? i.price.id : i?.plan?.id))
    .filter((id: unknown): id is string => typeof id === 'string' && id.length > 0);
}

/** True when a subscription carries at least one price we grant premium for. */
export function subscriptionIsEntitling(sub: any): boolean {
  return subscriptionPriceIds(sub).some((id) => ENTITLING_PRICE_IDS.includes(id));
}

/**
 * Parameters for the checkout session, separated from the call that sends them
 * so they can be asserted without a Stripe account (test/checkout.test.ts).
 *
 * They were not always assertable, and the cost of that showed: this object
 * carried `customer_creation: 'always'`, which Stripe accepts ONLY in payment
 * mode. In subscription mode it is a hard 400 — "`customer_creation` can only be
 * used in `payment` mode" — so every click of the website's one buy button died
 * at the API and rendered the generic error page. Nothing caught it, because
 * nothing could see this object without spending a live API call.
 *
 * The parameter was there to guarantee a Customer for every purchase:
 * `customer.subscription.*` webhooks carry a customer id and nothing else we can
 * resolve, so a guest checkout would leave renewals unattributable. Subscription
 * mode creates a Customer unconditionally, so dropping the parameter keeps the
 * guarantee and loses only the 400.
 */
export function checkoutSessionParams(baseUrl: string): Stripe.Checkout.SessionCreateParams {
  return {
    mode: 'subscription',
    line_items: [{ price: PRICE_ID, quantity: 1 }],
    success_url: `${baseUrl}/subscribe/success`,
    cancel_url: `${baseUrl}/subscribe/cancel`,
  };
}

export const StripeService = {

  /**
   * A Checkout session for the website's subscribe button. Stripe collects the
   * email itself — it is the identifier the whole claim flow hangs off, so it is
   * gathered by the one party already entitled to see it.
   */
  async createCheckout(baseUrl: string): Promise<string> {
    const session = await stripeClient().checkout.sessions.create(checkoutSessionParams(baseUrl));
    if (!session.url) throw new Error("Stripe returned a checkout session with no URL");
    return session.url;
  },

  /** Verify and parse a raw webhook payload using the signing secret. */
  constructEvent(rawBody: Buffer, signature: string) {
    return stripeClient().webhooks.constructEvent(
      rawBody,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  },

  /**
   * Stamp the email hash onto the Stripe customer.
   *
   * `subscription_customers` already maps the customer id to the hash, and that
   * is what the webhook reads. This is the backup copy: if the database is ever restored from a
   * point before a purchase, the subscriptions themselves can be rebuilt from
   * Stripe, which is the system of record for who paid. Best-effort by design —
   * a customer that cannot be tagged must not fail the checkout that created it.
   */
  async tagCustomerEmailHash(customerId: string, emailHash: string): Promise<void> {
    try {
      await stripeClient().customers.update(customerId, { metadata: { email_hash: emailHash } });
    } catch (e: any) {
      logger.warn(`[stripe] could not tag customer ${customerId}: ${e?.message || e}`);
    }
  },

  /**
   * A customer's email address, straight from Stripe.
   *
   * Needed only for a subscription an operator created in the dashboard: it
   * produced no Checkout Session, so no `checkout.session.completed` carried an
   * address, and the whole claim flow is keyed on one. Stripe is the system of
   * record for who is entitled, so this asks it.
   */
  async customerEmail(customerId: string): Promise<string | null> {
    try {
      const customer = await stripeClient().customers.retrieve(customerId);
      if ((customer as any)?.deleted) return null;
      return ((customer as any)?.email as string) || null;
    } catch (e: any) {
      logger.warn(`[stripe] could not read customer ${customerId}: ${e?.message || e}`);
      return null;
    }
  },

  /** The email hash recorded on a customer, for the recovery path above. */
  async emailHashForCustomer(customerId: string): Promise<string | null> {
    try {
      const customer = await stripeClient().customers.retrieve(customerId);
      return ((customer as any)?.metadata?.email_hash as string) || null;
    } catch (e: any) {
      logger.warn(`[stripe] could not read customer ${customerId}: ${e?.message || e}`);
      return null;
    }
  },
};
