// routes/member/billing.js
const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Leader = require('../../models/member_models/leader');

// Guard: only leaders should access billing actions
function requireLeader(req, res, next) {
  if (!req.isAuthenticated?.() || req.user?.membershipType !== 'leader') {
    return res.redirect('/login');
  }
  next();
}

// POST /billing/cancel   body: { mode: 'period_end' | 'immediate', reason?: string }
router.post('/billing/cancel', requireLeader, async (req, res) => {
  try {
    const { mode } = req.body;
    const leader = await Leader.findById(req.user._id);

    if (!leader || !leader.stripeSubscriptionId) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Cancellation Error',
        errorMessage: 'No active subscription found.'
      });
    }

    const subId = leader.stripeSubscriptionId;
    let whenText = 'cancelled';
    let cancelAt = null;

    if (mode === 'immediate') {
      await stripe.subscriptions.cancel(subId);
      leader.subscriptionStatus = 'cancelled';
      await leader.save();
      whenText = 'cancelled';
    } else {
      const updated = await stripe.subscriptions.update(subId, { cancel_at_period_end: true });
      leader.subscriptionStatus = 'cancelled'; // or store a separate flag if you prefer
      await leader.save();
      whenText = 'cancellation scheduled';
      if (updated.cancel_at) cancelAt = new Date(updated.cancel_at * 1000).toLocaleString();
    }

    return res.render('member_form_views/cancel_success', {
      layout: 'memberformlayout',
      when: whenText,
      cancelAt,
      subscriptionId: subId,
      dashboardPath: '/dashboard/leader',
      supportEmail: 'info@twennie.com'
    });
  } catch (err) {
    console.error('Cancel subscription error:', err.message);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Cancellation Error',
      errorMessage: 'We could not cancel your subscription. Please contact support.'
    });
  }
});

// (Optional) Stripe Billing Portal for self-serve changes
router.post('/billing/portal', requireLeader, async (req, res) => {
  try {
    const leader = await Leader.findById(req.user._id);
    if (!leader || !leader.stripeCustomerId) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Billing Portal',
        errorMessage: 'No Stripe customer found for this account.'
      });
    }

    const base = process.env.BASE_URL || `https://${req.get('host')}`;
    const portal = await stripe.billingPortal.sessions.create({
      customer: leader.stripeCustomerId,
      return_url: `${base}/dashboard/leader`
    });

    return res.redirect(303, portal.url);
  } catch (e) {
    console.error('Billing portal error:', e.message);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Billing Portal',
      errorMessage: 'Unable to open billing portal.'
    });
  }
});

module.exports = router;
