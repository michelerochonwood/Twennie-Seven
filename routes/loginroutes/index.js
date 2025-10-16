// routes/loginroutes.js
const express = require('express');
const passport = require('passport');
const router = express.Router();
const loginController = require('../../controllers/loginController');

// ---------- Helpers ----------
function redirectFor(user) {
  const t =
    user?.membershipType ||
    (user?.groupLeaderEmail ? 'leader' : (user?.groupId ? 'group_member' : 'member'));

  if (t === 'leader') return '/dashboard/leader';
  if (t === 'group_member') return '/dashboard/groupmember';
  return '/dashboard/member';
}

// After OAuth, block inactive accounts (cancelled users)
function blockInactiveAfterOAuth(req, res, next) {
  if (req.user && req.user.isActive === false) {
    req.logout?.(() => {});
    req.session?.destroy?.(() => {});
    return res.status(403).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Account Inactive',
      errorMessage:
        'Your account is inactive. Please contact support to reinstate your membership.'
    });
  }
  return next();
}

// ---------- Routes ----------

// Render login page
router.get('/login', loginController.showLoginForm);

// Local login (controller blocks inactive accounts)
router.post('/login', loginController.handleLogin);

// Logout
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    // destroy the session cookie + store record
    req.session?.destroy(() => {
      res.clearCookie?.('connect.sid'); // optional but tidy
      console.log('Logout successful');
      return res.redirect('/auth/login');
    });
  });
});


// --- Inactive account + Reactivation (works for all membership types) ---
router.get('/inactive', loginController.showInactiveAccount);
router.post('/reactivate', loginController.requestReactivation);

// ---------- Google Authentication ----------

// Start Google OAuth
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback after Google login
router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  blockInactiveAfterOAuth, // prevent cancelled users from logging in via Google
  (req, res) => {
    const to = redirectFor(req.user) || '/dashboard';
    return res.redirect(to);
  }
);

module.exports = router;



