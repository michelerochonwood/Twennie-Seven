const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

// Stripe requires raw body for signature verification
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!endpointSecret) {
    console.error('❌ STRIPE_WEBHOOK_SECRET is not set.');
    return res.status(500).send('Webhook secret not configured.');
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed.');
    console.error('Stripe Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        console.log(`✅ Checkout completed for session: ${session.id}`);

        const memberId = session.metadata?.memberId || null;
        const leaderId = session.metadata?.leaderId || null;

        if (memberId) {
          await Member.findByIdAndUpdate(memberId, {
            $set: {
              stripeCustomerId: session.customer || null,
              stripeSubscriptionId: session.subscription || null,
              paymentStatus: 'paid',
              subscriptionStatus: 'active',
              isActive: true
            }
          });
          console.log(`✅ Member updated from checkout.session.completed: ${memberId}`);
        }

        if (leaderId) {
          await Leader.findByIdAndUpdate(leaderId, {
            $set: {
              stripeCustomerId: session.customer || null,
              stripeSubscriptionId: session.subscription || null,
              paymentStatus: 'paid',
              subscriptionStatus: 'active',
              isActive: true
            }
          });
          console.log(`✅ Leader updated from checkout.session.completed: ${leaderId}`);
        }

        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        const subscriptionId = invoice.subscription;
        const customerId = invoice.customer;

        console.log(`✅ Payment succeeded for subscription: ${subscriptionId}`);

        const memberUpdated = await Member.findOneAndUpdate(
          {
            $or: [
              { stripeSubscriptionId: subscriptionId },
              { stripeCustomerId: customerId }
            ]
          },
          {
            $set: {
              paymentStatus: 'paid',
              subscriptionStatus: 'active',
              isActive: true
            }
          },
          { new: true }
        );

        if (memberUpdated) {
          console.log(`✅ Member marked paid: ${memberUpdated._id}`);
          break;
        }

        const leaderUpdated = await Leader.findOneAndUpdate(
          {
            $or: [
              { stripeSubscriptionId: subscriptionId },
              { stripeCustomerId: customerId }
            ]
          },
          {
            $set: {
              paymentStatus: 'paid',
              subscriptionStatus: 'active',
              isActive: true
            }
          },
          { new: true }
        );

        if (leaderUpdated) {
          console.log(`✅ Leader marked paid: ${leaderUpdated._id}`);
        }

        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        console.log(`ℹ️ Subscription updated: ${subscription.id}`);

        const update = {
          stripeCustomerId: subscription.customer || null,
          stripeSubscriptionId: subscription.id,
          cancelAt: subscription.cancel_at ? new Date(subscription.cancel_at * 1000) : null,
          subscriptionStatus: subscription.cancel_at_period_end ? 'cancel_at_period_end' : 'active'
        };

        const memberUpdated = await Member.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          { $set: update },
          { new: true }
        );

        if (memberUpdated) {
          console.log(`✅ Member subscription updated: ${memberUpdated._id}`);
          break;
        }

        const leaderUpdated = await Leader.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          { $set: update },
          { new: true }
        );

        if (leaderUpdated) {
          console.log(`✅ Leader subscription updated: ${leaderUpdated._id}`);
        }

        break;
      }

      case 'customer.subscription.deleted':
      case 'customer.subscription.canceled': {
        const subscription = event.data.object;
        console.log(`⚠️ Subscription canceled or deleted: ${subscription.id}`);

        const memberUpdated = await Member.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          {
            $set: {
              subscriptionStatus: 'canceled',
              paymentStatus: 'cancelled',
              isActive: false,
              accessLevel: 'free_individual',
              cancelAt: null
            }
          },
          { new: true }
        );

        if (memberUpdated) {
          console.log(`✅ Member canceled from Stripe webhook: ${memberUpdated._id}`);
          break;
        }

        const leaderUpdated = await Leader.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          {
            $set: {
              subscriptionStatus: 'canceled',
              paymentStatus: 'cancelled',
              isActive: false,
              cancelAt: null
            }
          },
          { new: true }
        );

        if (leaderUpdated) {
          console.log(`✅ Leader canceled from Stripe webhook: ${leaderUpdated._id}`);

          await GroupMember.updateMany(
            { leader: leaderUpdated._id },
            { $set: { isActive: false } }
          );

          console.log(`✅ Group members deactivated for leader: ${leaderUpdated._id}`);
        }

        break;
      }

      default:
        console.log(`ℹ️ Unhandled event type: ${event.type}`);
    }

    return res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook processing error:', err);
    return res.status(500).send('Webhook handler failed.');
  }
});

module.exports = router;
