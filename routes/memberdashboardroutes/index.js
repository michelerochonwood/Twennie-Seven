const express = require('express');
const router = express.Router();
const memberDashboardController = require('../../controllers/memberdashboardController');

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session?.user) {
    console.log(`User authenticated: ${req.session.user.username}`);
    return next();
  }
  console.warn('Access denied. Redirecting to login.');
  return res.redirect('/auth/login');
};

// GET /dashboard/member
router.get('/', isAuthenticated, async (req, res, next) => {
  try {
    console.log('Rendering member dashboard...');
    console.log('Session at start of /dashboard/member route:', req.session);

    await memberDashboardController.renderMemberDashboard(req, res);

    console.log('Member dashboard rendered successfully.');
  } catch (err) {
    console.error('❌ Error in member dashboard route:', err.message);
    next(err);
  }
});

// POST /dashboard/member/account/details
router.post('/account/details', isAuthenticated, async (req, res, next) => {
  try {
    console.log('POST /dashboard/member/account/details');
    await memberDashboardController.updateAccountDetails(req, res);
  } catch (err) {
    console.error('Error updating member account details:', err);
    next(err);
  }
});

// POST /dashboard/member/account/email-preferences
router.post('/account/email-preferences', isAuthenticated, async (req, res, next) => {
  try {
    console.log('POST /dashboard/member/account/email-preferences');
    await memberDashboardController.updateEmailPreferences(req, res);
  } catch (err) {
    console.error('Error updating member email preferences:', err);
    next(err);
  }
});

module.exports = router;







