const express = require('express');

const router = express.Router();

const groupMemberDashboardController = require('../../controllers/groupmemberdashboardController');


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
// --- POST /dashboard/groupmember/mark-seen ---
// Persist "last seen" count for a tab so green dots only show on increases
router.post('/mark-seen', isAuthenticated, async (req, res, next) => {
  try {
    await groupMemberDashboardController.markGroupMemberTabSeen(req, res);
  } catch (err) {
    console.error('Error marking group member tab seen:', err);
    next(err);
  }
});

module.exports = router;




