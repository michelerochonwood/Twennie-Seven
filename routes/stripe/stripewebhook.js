const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Stripe requires raw body for signature verification
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!endpointSecret) {
    console.error("❌ STRIPE_WEBHOOK_SECRET is not set.");
    return res.status(500).send("Webhook secret not configured.");
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed.');
    console.error('Stripe Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ✅ Handle supported event types
  switch (event.type) {
    case 'invoice.payment_succeeded': {
      const payment = event.data.object;
      console.log(`✅ Payment succeeded for subscription: ${payment.subscription}`);
      // TODO: Find user by subscription ID or customer ID and update their record
      break;
    }

    case 'customer.subscription.deleted':
    case 'customer.subscription.canceled': {
      const subscription = event.data.object;
      console.log(`⚠️ Subscription canceled or deleted: ${subscription.id}`);
      // TODO: Downgrade user's access or mark them as unpaid
      break;
    }

    case 'checkout.session.completed': {
      const session = event.data.object;
      console.log(`✅ Checkout completed for session: ${session.id}`);
      // Optional: Handle any post-checkout logic here
      break;
    }

    default:
      console.log(`ℹ️ Unhandled event type: ${event.type}`);
  }

  res.json({ received: true });
});

module.exports = router;

