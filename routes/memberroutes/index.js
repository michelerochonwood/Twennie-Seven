const express = require('express');
const router = express.Router();

const memberController = require('../../controllers/memberController');
const Member = require('../../models/member_models/member'); // Needed for /check-username

// ⬇️ NEW: used by /payment/success to persist Stripe IDs
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Leader = require('../../models/member_models/leader');

// 🟢 New Member Registration Form (GET + POST)
router.get('/form', memberController.showMemberForm);
router.post('/form', memberController.createMember);

// 🟢 New Free Member Registration Form (GET only — form posts to same /form endpoint)
router.get('/free-form', (req, res) => {
  res.render('member_form_views/free_individual', {
    layout: 'memberformlayout',
    csrfToken: req.csrfToken()
  });
});

// 🟢 Choose Membership Landing Page
router.get('/choose', (req, res) => {
  res.render('member_form_views/choose_membership', {
    layout: 'memberformlayout'
  });
});

// ✅ Stripe Payment Success Page (captures subscription & renders payment_success)
router.get('/payment/success', async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Payment Error',
        errorMessage: 'Missing session_id on success URL.'
      });
    }

    // Pull from Stripe (expand for convenience)
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['customer', 'subscription']
    });

    const subId = typeof session.subscription === 'string'
      ? session.subscription
      : session.subscription?.id;

    const customerId = typeof session.customer === 'string'
      ? session.customer
      : session.customer?.id;

    // Identify WHO to update
    const hintedType =
      req.user?.membershipType || req.session.user?.membershipType;

    const subMeta = (typeof session.subscription === 'object' && session.subscription?.metadata) || {};
    const memberIdFromMeta = subMeta.memberId;

    const custMeta = (typeof session.customer === 'object' && session.customer?.metadata) || {};
    const leaderIdFromMeta = custMeta.leaderId;

    let updatedUserType = null;

    if (subId && (leaderIdFromMeta || hintedType === 'leader')) {
      const leaderId = leaderIdFromMeta || req.user?._id || req.session.user?.id;
      if (leaderId) {
        const leader = await Leader.findById(leaderId);
        if (leader) {
          if (customerId) leader.stripeCustomerId = customerId;
          leader.stripeSubscriptionId = subId;
          leader.subscriptionStatus = 'active';
          leader.paymentStatus = 'paid';
          await leader.save();
          updatedUserType = 'leader';
        }
      }
    }

    if (!updatedUserType && subId && (memberIdFromMeta || hintedType === 'member')) {
      const memberId = memberIdFromMeta || req.user?._id || req.session.user?.id;
      if (memberId) {
        const member = await Member.findById(memberId);
        if (member) {
          if (customerId) member.stripeCustomerId = customerId;
          member.stripeSubscriptionId = subId;
          if ('subscriptionStatus' in member) member.subscriptionStatus = 'active';
          if ('paymentStatus' in member) member.paymentStatus = 'paid';
          await member.save();
          updatedUserType = 'member';
        }
      }
    }

    const username =
      req.session.user?.username || req.user?.username || 'User';
    const dashboardLink =
      updatedUserType === 'member'
        ? '/dashboard/member'
        : '/dashboard/leader';

    return res.render('member_form_views/payment_success', {
      layout: 'memberformlayout',
      title: 'Payment Successful',
      username,
      subscriptionId: subId,
      dashboardLink
    });
  } catch (err) {
    console.error('Success route error:', err.message);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Payment Error',
      errorMessage: 'We recorded your payment but could not finalize setup. Please contact support.'
    });
  }
});

// ✅ Stripe Payment Cancel Page
router.get('/payment/cancel', (req, res) => {
  res.render('member_form_views/error', {
    layout: 'memberformlayout',
    title: 'Payment Canceled',
    errorMessage: 'Your payment was canceled. You can try again anytime or contact support.'
  });
});

// ✅ Registration success page (non-paid members)
router.get('/register_success', (req, res) => {
  const username = req.session.user?.username || 'User';
  res.render('member_form_views/register_success', {
    layout: 'memberformlayout',
    title: 'Registration Successful',
    username,
    dashboardLink: '/dashboard/member'
  });
});

// ✅ AJAX username availability check
router.get('/check-username', async (req, res) => {
  const { username } = req.query;
  const user = await Member.findOne({ username });
  res.json({ available: !user });
});

module.exports = router;






