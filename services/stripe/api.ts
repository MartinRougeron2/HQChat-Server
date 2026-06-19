import Stripe from 'stripe';
import { DB } from '../db/api';
import { blindedPk as hashPk } from '../../lib/crypto-utils';

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

const PRICE_ID = 'price_1TjySfKdAg16VdMqoBBdqisu';
// Public origin for Stripe redirect URLs (was a myapp.com placeholder).
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://chat.martinrougeron.me';

export const StripeService = {

  async syncAndGetStatus(pk: string): Promise<{ active: boolean, checkoutUrl?: string }> {
    // Generate the blinded identifier
    const blindedPk = hashPk(pk);
    let customerId = await DB.getStripeId(blindedPk);

    // A. FIND OR CREATE STRIPE CUSTOMER
    if (!customerId) {
      // Search Stripe using the HASHED metadata
      const search = await stripeClient().customers.search({
        query: `metadata['blinded_pk']:'${blindedPk}'`,
      });

      if (search.data.length > 0 && search.data[0]) {
        customerId = search.data[0].id;
      } else {
        // Create New Customer with blinded metadata
        const newCus = await stripeClient().customers.create({
          // Avoid using PK in the name for better privacy
          name: `Protected User ${blindedPk.substring(0, 8)}`,
          metadata: { blinded_pk: blindedPk }
        });
        customerId = newCus.id;
      }

      await DB.updateUserTier(blindedPk, 'free', customerId ?? "");
    }

    // B. CHECK SUBSCRIPTION STATUS
    const subscriptions = await stripeClient().subscriptions.list({
      customer: customerId,
      status: 'active',
      limit: 1
    });

    const isPaid = subscriptions.data.length > 0;

    // C. UPDATE REDIS
    if (isPaid) {
      await DB.updateUserTier(blindedPk, 'premium');
      return { active: true };
    } else {
      await DB.updateUserTier(blindedPk, 'free');

      // D. GENERATE CHECKOUT URL
      const session = await stripeClient().checkout.sessions.create({
        customer: customerId,
        mode: 'subscription',
        line_items: [{ price: PRICE_ID, quantity: 1 }],
        success_url: `${PUBLIC_BASE_URL}/subscribe/success`,
        cancel_url: `${PUBLIC_BASE_URL}/subscribe/cancel`,
        // Optional: Pass the blinded PK to the session for webhook verification later
        client_reference_id: blindedPk
      });

      return { active: false, checkoutUrl: session.url! };
    }
  },

  /**
   * Web checkout for the iOS "linking code" flow: the user already has their
   * blinded PK (SHA-256 of their public key) from the app, so we bind the
   * Stripe customer to it directly instead of re-hashing a raw key.
   * Returns { active } if already subscribed, else a checkout URL.
   */
  async createWebCheckout(
    blindedPk: string,
    baseUrl: string
  ): Promise<{ active: boolean; checkoutUrl?: string }> {
    let customerId = await DB.getStripeId(blindedPk);

    if (!customerId) {
      const search = await stripeClient().customers.search({
        query: `metadata['blinded_pk']:'${blindedPk}'`,
      });
      if (search.data.length > 0 && search.data[0]) {
        customerId = search.data[0].id;
      } else {
        const newCus = await stripeClient().customers.create({
          name: `Protected User ${blindedPk.substring(0, 8)}`,
          metadata: { blinded_pk: blindedPk },
        });
        customerId = newCus.id;
      }
      await DB.updateUserTier(blindedPk, 'free', customerId ?? '');
    }

    const subscriptions = await stripeClient().subscriptions.list({
      customer: customerId,
      status: 'active',
      limit: 1,
    });
    if (subscriptions.data.length > 0) {
      await DB.updateUserTier(blindedPk, 'premium');
      return { active: true };
    }

    const session = await stripeClient().checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: `${baseUrl}/subscribe/success`,
      cancel_url: `${baseUrl}/subscribe/cancel`,
      client_reference_id: blindedPk,
    });
    return { active: false, checkoutUrl: session.url! };
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
   * Apply a subscription state change. Resolves the customer back to its
   * blinded_pk (the key the rest of the app uses) and updates the tier in
   * Redis so access flips in real time instead of only at next connect.
   */
  async handleSubscriptionChange(customerId: string, active: boolean) {
    const customer = await stripeClient().customers.retrieve(customerId);
    const blindedPk = (customer as any)?.metadata?.blinded_pk as string | undefined;
    if (!blindedPk) {
      console.log(`⚠️ [stripe] No blinded_pk on customer ${customerId}; ignoring`);
      return;
    }
    await DB.updateUserTier(blindedPk, active ? 'premium' : 'free');
    console.log(`💳 [stripe] ${blindedPk.substring(0, 8)} → ${active ? 'premium' : 'free'}`);
  },

  async getCustomerId(blindedPk: string): Promise<string | null> {
    let customerId = await DB.getStripeId(blindedPk);
    if (!customerId) {
      const search = await stripeClient().customers.search({
        query: `metadata['blinded_pk']:'${blindedPk}'`,
      });
      if (search.data.length > 0 && search.data[0]) {
        customerId = search.data[0].id;
      }
    }
    return customerId ?? null;
  },

  async getCustomerPageUrl(customerId: string): Promise<string | null> {
    const portalSession = await stripeClient().billingPortal.sessions.create({
      customer: customerId,
      return_url: `${PUBLIC_BASE_URL}/subscribe`,
    });
    return portalSession.url ?? null;
  }
};