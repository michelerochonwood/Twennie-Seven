const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');              // <-- add this
const memberDashboardController = require('../../controllers/memberdashboardController');
const DashboardSeen = require('../../models/dashboard_seen'); 

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

router.post('/mark-seen', isAuthenticated, async (req, res) => {
  try {
    const rawId = req.session?.user?.id || req.user?._id;
    if (!rawId) return res.status(401).json({ ok: false, reason: 'unauthorized' });

    const { tab, count } = req.body || {};
    if (!tab || typeof count !== 'number' || Number.isNaN(count)) {
      return res.status(400).json({ ok: false, reason: 'bad payload' });
    }

    const userId = new mongoose.Types.ObjectId(String(rawId));
    const update = {
      $set: {
        [`tabs.${tab}.count`]: count,
        [`tabs.${tab}.seenAt`]: new Date()
      }
    };

    const doc = await DashboardSeen.findOneAndUpdate(
      { userId, role: 'member' },
      update,
      { new: true, upsert: true }
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error('member mark-seen error:', e);
    return res.status(500).json({ ok: false, reason: 'server' });
  }
});

module.exports = router;







