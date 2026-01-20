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
    req.session?.destroy(() => {
      res.clearCookie?.('connect.sid');
      console.log('Logout successful');
      return res.redirect('/auth/login');
    });
  });
});

// Inactive account + Reactivation
router.get('/inactive', loginController.showInactiveAccount);
router.post('/reactivate', loginController.requestReactivation);

// ---------- Google Authentication ----------
// NOTE: since this router is mounted at /auth,
// these become /auth/google and /auth/google/callback

router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get(
  '/google/callback',
passport.authenticate('google', { failureRedirect: '/auth/login?error=google' }),

  blockInactiveAfterOAuth,
  (req, res) => {
    const to = redirectFor(req.user) || '/dashboard/member';

    // Optional: keep your session.user pattern consistent
    // (harmless even if you rely on req.user elsewhere)
    if (req.user?._id) {
      req.session.user = {
        id: req.user._id.toString(),
        username: req.user.username || req.user.name || req.user.groupLeaderName || 'User',
        membershipType: req.user.membershipType || 'member',
        accessLevel: req.user.accessLevel || 'free_individual',
        organization: req.user.organization || null,
        groupId: req.user.groupId ? req.user.groupId.toString() : null,
      };
    }

    return res.redirect(to);
  }
);

module.exports = router;



