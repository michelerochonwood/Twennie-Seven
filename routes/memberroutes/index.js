const express = require('express');
const router = express.Router();
const memberController = require('../../controllers/memberController');
const Member = require('../../models/member_models/member'); // Needed for /check-username

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

// ✅ Stripe Payment Success Page
router.get('/payment/success', (req, res) => {
  const username = req.session.user?.username || 'User';
  const membershipType = req.session.user?.membershipType;
  const dashboardLink =
    membershipType === 'leader' ? '/dashboard/leader' : '/dashboard/member';

  res.render('member_form_views/register_success', {
    layout: 'memberformlayout',
    title: 'Registration Successful',
    username,
    dashboardLink
  });
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





