// billing/stripeSeats.js
const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' });

/**
 * Sync a leader's billed seat quantity to Stripe.
 * Uses leader.getSeatQuantity() (from your schema).
 * Returns the final quantity pushed to Stripe (or cached if not yet subscribed).
 */
async function syncLeaderSeatQuantity(leader, { proration = true, reason = 'unspecified' } = {}) {
  const qty = leader.getSeatQuantity();

  if (!leader?.stripeSubscriptionItemId) {
    // Not subscribed yet (e.g., pre-checkout). Cache for UI and exit.
    leader.lastSeatQuantity = qty;
    leader.lastSeatSyncAt = new Date();
    await leader.save();
    return qty;
  }

  await stripe.subscriptionItems.update(leader.stripeSubscriptionItemId, {
    quantity: qty,
    proration_behavior: proration ? 'create_prorations' : 'none',
    metadata: { seat_sync_reason: reason }
  });

  leader.lastSeatQuantity = qty;
  leader.lastSeatSyncAt = new Date();
  await leader.save();
  return qty;
}

module.exports = { syncLeaderSeatQuantity };
