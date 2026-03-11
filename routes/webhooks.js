// routes/webhooks.js
const express = require('express');
const router = express.Router();
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16'
});

const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

// Stripe requires raw body for signature verification.
// IMPORTANT:
// - This route path is /stripe
// - If mounted with app.use('/webhooks', webhookRoutes),
//   the full endpoint URL in Stripe must be:
//   https://www.twennie.com/webhooks/stripe
router.post('/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log('🔥 Incoming request to /webhooks/stripe');

  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!endpointSecret) {
    console.error('❌ STRIPE_WEBHOOK_SECRET is not set.');
    return res.status(500).send('Webhook secret not configured.');
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    console.log('🔥 Stripe webhook received:', event.type);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed.');
    console.error('Stripe Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;

        console.log('🔥 checkout.session.completed payload', {
          sessionId: session.id,
          mode: session.mode,
          metadata: session.metadata,
          subscription: session.subscription,
          customer: session.customer,
          subscription_details: session.subscription_details
        });

        if (session.mode !== 'subscription') {
          console.log(`ℹ️ Ignoring non-subscription checkout session: ${session.id}`);
          break;
        }

        const subId = session.subscription || null;
        const customerId = session.customer || null;

        const memberId =
          session.metadata?.memberId ||
          session.metadata?.member_id ||
          session.subscription_details?.metadata?.memberId ||
          session.subscription_details?.metadata?.member_id ||
          null;

        const leaderId =
          session.metadata?.leaderId ||
          session.metadata?.leader_id ||
          session.subscription_details?.metadata?.leaderId ||
          session.subscription_details?.metadata?.leader_id ||
          null;

        console.log('🔥 Resolved IDs from checkout session', {
          memberId,
          leaderId
        });

        if (!memberId && !leaderId) {
          console.warn('⚠️ No memberId or leaderId found in checkout session metadata', {
            sessionId: session.id,
            metadata: session.metadata,
            subscription_details: session.subscription_details
          });
          break;
        }

        if (memberId) {
          const updatedMember = await Member.findByIdAndUpdate(
            memberId,
            {
              $set: {
                stripeCustomerId: customerId,
                stripeSubscriptionId: subId,
                paymentStatus: 'paid',
                subscriptionStatus: 'active',
                isActive: true,
                cancelAt: null
              }
            },
            { new: true }
          );

          if (updatedMember) {
            console.log(`✅ Member updated from checkout.session.completed: ${memberId}`);
          } else {
            console.warn(`⚠️ No Member found for checkout.session.completed: ${memberId}`);
          }
        }

        if (leaderId) {
          const leader = await Leader.findById(leaderId).populate('members');

          if (!leader) {
            console.warn(`⚠️ No Leader found for checkout.session.completed: ${leaderId}`);
            break;
          }

          let stripeSubscriptionItemId = leader.stripeSubscriptionItemId || null;
          let stripePriceId = leader.stripePriceId || null;

          if (subId) {
            const sub = await stripe.subscriptions.retrieve(subId, {
              expand: ['items.data.price']
            });

            const seatItem = sub.items?.data?.[0] || null;
            stripeSubscriptionItemId = seatItem?.id || null;
            stripePriceId = seatItem?.price?.id || process.env.STRIPE_PRICE_SEAT || null;

            leader.subscriptionStatus = sub.status === 'active' ? 'active' : 'pending';
          }

          leader.stripeCustomerId = customerId;
          leader.stripeSubscriptionId = subId;
          leader.stripeSubscriptionItemId = stripeSubscriptionItemId;
          leader.stripePriceId = stripePriceId;
          leader.paymentStatus = 'paid';
          leader.isActive = true;
          leader.cancelAt = null;
          leader.lastSeatQuantity =
            typeof leader.getSeatQuantity === 'function'
              ? leader.getSeatQuantity()
              : (leader.members?.length || 0);
          leader.lastSeatSyncAt = new Date();

          await leader.save();
          console.log(`✅ Leader updated from checkout.session.completed: ${leaderId}`);
        }

        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        const subscriptionId = invoice.subscription || null;
        const customerId = invoice.customer || null;

        console.log(`✅ invoice.payment_succeeded: subscription=${subscriptionId}, customer=${customerId}`);

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
          console.log(`✅ Member marked paid from invoice: ${memberUpdated._id}`);
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
          console.log(`✅ Leader marked paid from invoice: ${leaderUpdated._id}`);
        } else {
          console.log('ℹ️ No member or leader matched invoice.payment_succeeded');
        }

        break;
      }

      case 'customer.subscription.updated': {
        const sub = event.data.object;
        console.log(`ℹ️ customer.subscription.updated: ${sub.id}`);

        const leader = await Leader.findOne({ stripeSubscriptionId: sub.id }).populate('members');

        if (leader) {
          leader.stripeCustomerId = sub.customer || null;
          leader.stripeSubscriptionId = sub.id;
          leader.subscriptionStatus = sub.cancel_at_period_end
            ? 'cancel_at_period_end'
            : (sub.status || 'active');
          leader.cancelAt = sub.cancel_at ? new Date(sub.cancel_at * 1000) : null;

          if (leader.stripeSubscriptionItemId) {
            const shouldBe =
              typeof leader.getSeatQuantity === 'function'
                ? leader.getSeatQuantity()
                : (leader.members?.length || 0);

            const item = sub.items?.data?.find(i => i.id === leader.stripeSubscriptionItemId);
            const current = item?.quantity;

            if (typeof current === 'number' && current !== shouldBe) {
              await stripe.subscriptionItems.update(leader.stripeSubscriptionItemId, {
                quantity: shouldBe,
                proration_behavior: 'create_prorations'
              });

              leader.lastSeatQuantity = shouldBe;
              leader.lastSeatSyncAt = new Date();
              console.log(`🔁 Corrected seat qty for leader ${leader._id}: ${current} → ${shouldBe}`);
            }
          }

          await leader.save();
          console.log(`✅ Leader subscription updated: ${leader._id}`);
          break;
        }

        const memberUpdated = await Member.findOneAndUpdate(
          { stripeSubscriptionId: sub.id },
          {
            $set: {
              stripeCustomerId: sub.customer || null,
              stripeSubscriptionId: sub.id,
              subscriptionStatus: sub.cancel_at_period_end
                ? 'cancel_at_period_end'
                : (sub.status || 'active'),
              cancelAt: sub.cancel_at ? new Date(sub.cancel_at * 1000) : null
            }
          },
          { new: true }
        );

        if (memberUpdated) {
          console.log(`✅ Member subscription updated: ${memberUpdated._id}`);
        } else {
          console.log(`ℹ️ No member matched customer.subscription.updated: ${sub.id}`);
        }

        break;
      }

      case 'invoice.upcoming': {
        const invoice = event.data.object;
        const subscriptionId = invoice.subscription || null;

        console.log(`ℹ️ invoice.upcoming: subscription=${subscriptionId}`);

        if (!subscriptionId) break;

        const leader = await Leader.findOne({ stripeSubscriptionId: subscriptionId }).populate('members');

        if (leader?.stripeSubscriptionItemId) {
          const shouldBe =
            typeof leader.getSeatQuantity === 'function'
              ? leader.getSeatQuantity()
              : (leader.members?.length || 0);

          const sub = await stripe.subscriptions.retrieve(subscriptionId);
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

            console.log(`🔁 Corrected upcoming seat qty for leader ${leader._id}: ${current} → ${shouldBe}`);
          }
        }

        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        console.log(`⚠️ customer.subscription.deleted: ${sub.id}`);

        const memberUpdated = await Member.findOneAndUpdate(
          { stripeSubscriptionId: sub.id },
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
          { stripeSubscriptionId: sub.id },
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

          console.log(`✅ Group members deactivated for leader ${leaderUpdated._id}`);
        } else {
          console.log(`ℹ️ No member or leader matched customer.subscription.deleted: ${sub.id}`);
        }

        break;
      }

      default:
        console.log(`ℹ️ Unhandled event type: ${event.type}`);
        break;
    }

    return res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook handler error:', err);
    return res.status(500).send('Webhook handler error');
  }
});

module.exports = router;