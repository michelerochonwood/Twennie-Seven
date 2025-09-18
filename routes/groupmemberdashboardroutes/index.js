const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

const groupMemberDashboardController = require('../../controllers/groupmemberdashboardController');
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

// --- GET /dashboard/groupmember ---
router.get('/', isAuthenticated, async (req, res, next) => {
  try {
    await groupMemberDashboardController.renderGroupMemberDashboard(req, res);
  } catch (err) {
    console.error('Error in group member dashboard route:', err.message);
    next(err);
  }
});

// --- POST /dashboard/groupmember/account/details ---
router.post('/account/details', isAuthenticated, async (req, res, next) => {
  try {
    await groupMemberDashboardController.updateAccountDetails(req, res);
  } catch (err) {
    console.error('Error updating group member account details:', err);
    next(err);
  }
});

// --- POST /dashboard/groupmember/account/email-preferences ---
router.post('/account/email-preferences', isAuthenticated, async (req, res, next) => {
  try {
    await groupMemberDashboardController.updateEmailPreferences(req, res);
  } catch (err) {
    console.error('Error updating group member email preferences:', err);
    next(err);
  }
});

// --- POST /dashboard/groupmember/mark-seen ---
// Persist "last seen" count for a tab so green dots only show on increases
router.post('/mark-seen', isAuthenticated, async (req, res) => {
  try {
    const rawId = req.session?.user?.id || req.user?._id;
    if (!rawId) {
      console.warn('groupmember mark-seen: missing user');
      return res.status(401).json({ ok: false, reason: 'unauthorized' });
    }

    const { tab, count } = req.body || {};
    if (!tab || typeof count !== 'number' || Number.isNaN(count)) {
      console.warn('groupmember mark-seen: bad payload', req.body);
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
      { userId, role: 'group_member' },
      update,
      { new: true, upsert: true }
    );

    console.log('groupmember mark-seen OK:', { tab, count, saved: doc?.tabs?.get(tab) });
    return res.json({ ok: true });
  } catch (e) {
    console.error('groupmember mark-seen error:', e);
    return res.status(500).json({ ok: false, reason: 'server' });
  }
});

module.exports = router;




