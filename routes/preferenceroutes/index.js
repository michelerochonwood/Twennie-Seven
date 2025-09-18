// routes/preferenceroutes.js
const router = require('express').Router();
const {
  updateMemberPreferences,
  updateLeaderPreferences,
  updateGroupMemberPreferences
} = require('../../controllers/cookieController');

// Reuse your standard auth guard pattern
function isAuthenticated(req, res, next) {
  if ((typeof req.isAuthenticated === 'function' && req.isAuthenticated()) || req.session?.user) return next();
  return res.redirect('/auth/login');
}

// Member UI prefs: POST /dashboard/member/preferences
router.post('/member/preferences', isAuthenticated, updateMemberPreferences);

// Leader UI prefs: POST /dashboard/leader/preferences
router.post('/leader/preferences', isAuthenticated, updateLeaderPreferences);

// Group member UI prefs: POST /dashboard/groupmember/preferences
router.post('/groupmember/preferences', isAuthenticated, updateGroupMemberPreferences);

module.exports = router;
