// controllers/loginController.js
const bcrypt = require('bcrypt');
const passport = require('passport');

const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

function renderLoginError(res, req, msg) {
  return res.status(401).render('login_views/login_view', {
    layout: 'mainlayout',
    title: 'Login',
    error: msg,
    csrfToken: req.csrfToken ? req.csrfToken() : null,
  });
}

// Try each user type by email (member uses 'email', leader uses 'groupLeaderEmail')
async function findUserByEmailAllTypes(emailLower) {
  return (
    (await Member.findOne({ email: emailLower })) ||
    (await Leader.findOne({ groupLeaderEmail: emailLower })) ||
    (await GroupMember.findOne({ email: emailLower }))
  );
}

// Disallow login for inactive accounts
function blockInactive(user) {
  return user && user.isActive === false;
}

// Normalize downstream metadata (role, username, org, team anchor, redirect)
function normalizeUserMeta(user) {
  const membershipType =
    user.membershipType ||
    (user.groupLeaderEmail ? 'leader' : (user.groupId ? 'group_member' : 'member'));

  const username =
    user.username || user.groupLeaderName || user.name || user.groupMemberName || 'User';

  const organization = user.organization || null;
  let groupId = null;
  if (membershipType === 'leader') {
    groupId = user._id?.toString?.() || null; // leader anchors by their own id
  } else if (membershipType === 'group_member') {
    groupId = user.groupId ? user.groupId.toString() : null;
  }

  const accessLevel =
    membershipType === 'member'
      ? (user.accessLevel || 'free_individual')
      : membershipType; // leader | group_member

  const redirectByType = {
    leader: '/dashboard/leader',
    group_member: '/dashboard/groupmember',
    member: '/dashboard/member',
  };
  const redirectTo = redirectByType[membershipType] || '/';

  return { membershipType, username, organization, groupId, accessLevel, redirectTo };
}

module.exports = {
  // -------- Views --------
  showLoginForm: (req, res) => {
    console.log('Login page accessed');
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    res.render('login_views/login_view', {
      layout: 'mainlayout',
      title: 'Login',
      csrfToken,
    });
  },

  // -------- Handlers --------
  // 1) finds user by email across all types
  // 2) blocks inactive accounts (no LocalStrategy change needed)
  // 3) bcrypt compare
  // 4) supports MFA hold OR logs in + sets session
  handleLogin: async (req, res, next) => {
    const email = (req.body.email || '').toLowerCase();
    const password = req.body.password;

    console.log('Login attempt with email:', email);

    try {
      const user = await findUserByEmailAllTypes(email);

      if (!user) {
        console.warn(`❌ No user found for ${email}`);
        return renderLoginError(res, req, 'Invalid email or password.');
      }

      // 🔒 Block inactive accounts here
      if (blockInactive(user)) {
        console.warn(`🚫 Inactive account attempted login: ${email}`);
        return res.status(403).render('member_form_views/account_inactive', {
          layout: 'memberformlayout',
          title: 'Account Inactive',
          username: user.username || user.groupLeaderName || user.name || null,
          email: user.email || user.groupLeaderEmail || null,
          membershipType: user.membershipType || null,
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          supportEmail: 'info@twennie.com'
        });
      }

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        console.warn(`❌ Password mismatch for ${email}`);
        return renderLoginError(res, req, 'Invalid email or password.');
      }

      const { membershipType, username, organization, groupId, accessLevel, redirectTo } =
        normalizeUserMeta(user);

      // MFA branch (do NOT call req.login yet)
      if (user.mfa?.enabled) {
        req.session.pendingMfa = {
          userId: user._id.toString(),
          role:
            membershipType === 'leader'
              ? 'leader'
              : membershipType === 'group_member'
              ? 'group_member'
              : 'member',
          user: {
            id: user._id.toString(),
            username,
            membershipType,
            accessLevel,
            organization,
            groupId,
          },
          redirectTo,
        };
        console.log(`🔐 Password ok; MFA required for ${username}. Redirecting to challenge.`);
        return res.redirect('/mfa/challenge');
      }

      // No MFA: complete login
      req.login(user, (err) => {
        if (err) {
          console.error('❌ req.login error:', err);
          return next(err);
        }

        // Lightweight session payload for downstream code
        req.session.user = {
          id: user._id.toString(),
          username,
          membershipType,
          accessLevel,
          organization,
          groupId,
        };

        console.log(`✅ Login successful: ${username} (${membershipType})`);
        return res.redirect(redirectTo);
      });
    } catch (err) {
      console.error('❌ Login error:', err);
      return res.status(500).render('login_views/login_view', {
        layout: 'mainlayout',
        title: 'Login',
        error: 'An unexpected error occurred. Please try again.',
        csrfToken: req.csrfToken ? req.csrfToken() : null,
      });
    }
  },

  handleLogout: (req, res) => {
    req.logout?.(() => {});
    req.session.destroy(() => {
      console.log('Logout successful');
      res.redirect('/auth/login');
    });
  },

  // -------- New: Inactive account flow --------
  // GET /auth/inactive
  showInactiveAccount: (req, res) => {
    const u = req.user || req.session?.user || {};
    const csrfToken = req.csrfToken ? req.csrfToken() : null;

    return res.status(403).render('member_form_views/account_inactive', {
      layout: 'memberformlayout',
      title: 'Account Inactive',
      csrfToken,
      username: u.username || null,
      email: u.email || u.groupLeaderEmail || null,
      membershipType: u.membershipType || null,
      supportEmail: 'info@twennie.com'
    });
  },

  // POST /auth/reactivate
  requestReactivation: async (req, res) => {
    try {
      const { email, message, membershipType } = req.body || {};
      const csrfToken = req.csrfToken ? req.csrfToken() : null;

      if (!email) {
        return res.status(400).render('member_form_views/account_inactive', {
          layout: 'memberformlayout',
          title: 'Account Inactive',
          csrfToken,
          errorMessage: 'Please provide an email so we can contact you.',
          email,
          membershipType
        });
      }

      // Minimal: log the request for now (or persist/email later)
      console.log('📬 Reactivation request:', {
        email, membershipType: membershipType || 'unknown', message: message || ''
      });

      // OPTIONAL: persist to a collection
      // const ReactivationRequest = require('../models/member_models/reactivation_request');
      // await new ReactivationRequest({ email, membershipType, message }).save();

      // Re-use your success view for a friendly confirmation
      return res.render('member_form_views/change_success', {
        layout: 'memberformlayout',
        title: 'Request Received',
        username: email,
        dashboardLink: '/' // keep them away from dashboards while inactive
      });
    } catch (err) {
      console.error('❌ Reactivation request error:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Error',
        errorMessage: 'We could not process your request. Please email info@twennie.com.'
      });
    }
  }
};




