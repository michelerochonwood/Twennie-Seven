// controllers/billingController.js
const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' });
const Leader = require('../models/member_models/leader');
const { syncLeaderSeatQuantity } = require('../billings/stripeSeats');

function requireLeader(req, res, next) {
  // You said you use req.user (Passport). Adjust if different.
  if (req.user && req.user.accessLevel === 'leader') return next();
  return res.status(401).send('Unauthorized');
}

async function ensureStripeCustomer(leader) {
  if (leader.stripeCustomerId) return leader.stripeCustomerId;

  const customer = await stripe.customers.create({
    name: leader.groupLeaderName,
    email: leader.groupLeaderEmail,
    address: leader.billingAddress?.line1 ? {
      line1: leader.billingAddress.line1,
      line2: leader.billingAddress.line2,
      city: leader.billingAddress.city,
      state: leader.billingAddress.province,
      postal_code: leader.billingAddress.postalCode,
      country: leader.billingAddress.country || 'CA'
    } : undefined,
    metadata: {
      leader_id: leader._id.toString(),
      group_name: leader.groupName
    }
  });

  leader.stripeCustomerId = customer.id;
  await leader.save();
  return customer.id;
}

exports.startCheckout = [
  requireLeader,
  async (req, res) => {
    try {
      const leader = await Leader.findById(req.user._id).populate('members');
      if (!leader) return res.status(404).send('Leader not found');

      const customerId = await ensureStripeCustomer(leader);
      const qty = Math.max(leader.getSeatQuantity(), 1); // at least 1 seat

      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        customer: customerId,
        line_items: [{
          price: process.env.STRIPE_PRICE_SEAT, // you said this is set
          quantity: qty
        }],
        allow_promotion_codes: true,
        automatic_tax: { enabled: true },
        subscription_data: {
          metadata: {
            leader_id: leader._id.toString(),
            seat_billing_mode: leader.seatBillingMode
          }
        },
        success_url: `${process.env.APP_BASE_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.APP_BASE_URL}/billing/cancel`
      });

      res.redirect(303, session.url);
    } catch (err) {
      console.error('startCheckout error:', err);
      res.status(500).send('Unable to start checkout.');
    }
  }
];

exports.openPortal = [
  requireLeader,
  async (req, res) => {
    try {
      const leader = await Leader.findById(req.user._id);
      if (!leader?.stripeCustomerId) return res.status(400).send('No Stripe customer on file.');
      const portal = await stripe.billingPortal.sessions.create({
        customer: leader.stripeCustomerId,
        return_url: `${process.env.APP_BASE_URL}/dashboard/leader`
      });
      res.redirect(303, portal.url);
    } catch (err) {
      console.error('openPortal error:', err);
      res.status(500).send('Unable to open billing portal.');
    }
  }
];

exports.manualSeatSync = [
  requireLeader,
  async (req, res) => {
    try {
      const leader = await Leader.findById(req.user._id).populate('members');
      if (!leader) return res.status(404).send('Leader not found');
      const qty = await syncLeaderSeatQuantity(leader, { proration: true, reason: 'manual_sync' });
      res.json({ ok: true, quantity: qty });
    } catch (err) {
      console.error('manualSeatSync error:', err);
      res.status(500).json({ ok: false, error: 'Seat sync failed' });
    }
  }
];
