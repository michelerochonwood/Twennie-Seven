const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

const leaderDashboardController = require('../../controllers/leaderdashboardController');
const DashboardSeen = require('../../models/dashboard_seen');

// --- Auth gate ---
const isAuthenticated = (req, res, next) => {
  if (req.session?.user) {
    console.log(`User authenticated: ${req.session.user.username}`);
    return next();
  }
  console.warn('Access denied. Redirecting to login.');
  return res.redirect('/auth/login');
};

// --- GET /dashboard/leader ---
router.get('/', isAuthenticated, async (req, res, next) => {
  try {
    const dashboardData = await leaderDashboardController.renderLeaderDashboard(req, res);

    // Preserve your existing prompt-session logic
    if (dashboardData?.leaderPrompt1) {
      req.session.leaderPrompt1 = {
        promptSetId: dashboardData.leaderPrompt1.promptSetId?.toString(),
        promptIndex: Number(dashboardData.leaderPrompt1.promptIndex)
      };
      console.log('Session after setting leader prompt data:', req.session);
    } else {
      console.warn('No leader prompt data available to store in session.');
    }
  } catch (err) {
    console.error('Error in leader dashboard route:', err.message);
    next(err);
  }
});

// --- POST /dashboard/leader/account/details ---
router.post('/account/details', isAuthenticated, async (req, res, next) => {
  try {
    await leaderDashboardController.updateAccountDetails(req, res);
  } catch (err) {
    console.error('Error updating account details:', err);
    next(err);
  }
});

// --- POST /dashboard/leader/account/email-preferences ---
router.post('/account/email-preferences', isAuthenticated, async (req, res, next) => {
  try {
    await leaderDashboardController.updateEmailPreferences(req, res);
  } catch (err) {
    console.error('Error updating email preferences:', err);
    next(err);
  }
});

// --- POST /dashboard/leader/mark-seen ---
// Persist "last seen" count for a tab so green dots only show on increases
router.post('/mark-seen', isAuthenticated, async (req, res) => {
  try {
    const rawId = req.session?.user?.id || req.user?._id;
    if (!rawId) {
      console.warn('mark-seen: missing user');
      return res.status(401).json({ ok: false, reason: 'unauthorized' });
    }

    const { tab, count } = req.body || {};
    if (!tab || typeof count !== 'number' || Number.isNaN(count)) {
      console.warn('mark-seen: bad payload', req.body);
      return res.status(400).json({ ok: false, reason: 'bad payload' });
    }

    // Mongoose will cast strings, but we can be explicit:
    const userId = new mongoose.Types.ObjectId(String(rawId));

    const update = {
      $set: {
        [`tabs.${tab}.count`]: count,
        [`tabs.${tab}.seenAt`]: new Date()
      }
    };

    const doc = await DashboardSeen.findOneAndUpdate(
      { userId, role: 'leader' },
      update,
      { new: true, upsert: true }
    );

    console.log('mark-seen OK:', {
      tab,
      count,
      saved: doc?.tabs?.get(tab)
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('mark-seen error:', e);
    return res.status(500).json({ ok: false, reason: 'server' });
  }
});

module.exports = router;
