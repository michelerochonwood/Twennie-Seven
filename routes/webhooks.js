// routes/webhooks.js
const express = require('express');
const router = express.Router();
const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET, { apiVersion: '2023-10-16' });
const Leader = require('../models/member_models/leader');

// IMPORTANT: raw body ONLY for this route
router.post('/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode === 'subscription') {
          const subId = session.subscription;
          const sub = await stripe.subscriptions.retrieve(subId, { expand: ['items.data.price'] });

          const leaderId = sub.metadata?.leader_id || session.metadata?.leader_id;
          if (leaderId) {
            const leader = await Leader.findById(leaderId).populate('members');
            if (leader) {
              const seatItem = sub.items.data[0]; // single per-seat item
              leader.stripeSubscriptionId = sub.id;
              leader.subscriptionStatus = sub.status === 'active' ? 'active' : 'pending';
              leader.stripeSubscriptionItemId = seatItem.id;
              leader.stripePriceId = seatItem.price?.id || process.env.STRIPE_PRICE_SEAT;
              leader.lastSeatQuantity = leader.getSeatQuantity();
              leader.lastSeatSyncAt = new Date();
              await leader.save();
            }
          }
        }
        break;
      }

      case 'customer.subscription.updated':
      case 'invoice.upcoming': {
        // Safety net: enforce DB seat count
        const sub = event.data.object;
        const leader = await Leader.findOne({ stripeSubscriptionId: sub.id }).populate('members');
        if (leader?.stripeSubscriptionItemId) {
          const shouldBe = leader.getSeatQuantity();
          const item = sub.items?.data?.find(i => i.id === leader.stripeSubscriptionItemId);
          const current = item?.quantity;

          if (typeof current === 'number' && current !== shouldBe) {
            await stripe.subscriptionItems.update(leader.stripeSubscriptionItemId, {
              quantity: shouldBe,
              proration_behavior: 'create_prorations'
            });
            leader.lastSeatQuantity = shouldBe;
            leader.lastSeatSyncAt = new Date();
            await leader.save();
            console.log(`🔁 Corrected seat qty for leader ${leader._id}: ${current} → ${shouldBe}`);
          }
        }
        break;
      }

      default:
        // handle other events if needed
        break;
    }

    res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    res.status(500).send('Webhook handler error');
  }
});

module.exports = router;
