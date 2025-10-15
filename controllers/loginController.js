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

// Normalize downstream metadata
function normalizeUserMeta(user) {
  // membershipType normalization
  const membershipType =
    user.membershipType ||
    (user.groupLeaderEmail ? 'leader' : (user.groupId ? 'group_member' : 'member'));

  // username / display name
  const username =
    user.username || user.groupLeaderName || user.name || user.groupMemberName || 'User';

  // organization and team anchor
  const organization = user.organization || null;
  let groupId = null;
  if (membershipType === 'leader') {
    groupId = user._id?.toString?.() || null; // leader’s own id anchors their team
  } else if (membershipType === 'group_member') {
    groupId = user.groupId ? user.groupId.toString() : null;
  }

  // accessLevel
  const accessLevel =
    membershipType === 'member'
      ? (user.accessLevel || 'free_individual')
      : membershipType; // leader | group_member

  // post-login redirect
  const redirectByType = {
    leader: '/dashboard/leader',
    group_member: '/dashboard/groupmember',
    member: '/dashboard/member',
  };
  const redirectTo = redirectByType[membershipType] || '/';

  return { membershipType, username, organization, groupId, accessLevel, redirectTo };
}

module.exports = {
  showLoginForm: (req, res) => {
    console.log('Login page accessed');
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    res.render('login_views/login_view', {
      layout: 'mainlayout',
      title: 'Login',
      csrfToken,
    });
  },

  // Single controller that:
  // 1) finds the user by email across all types,
  // 2) blocks inactive accounts (without changing LocalStrategy),
  // 3) handles bcrypt compare,
  // 4) supports MFA hold, or logs in and sets your session.
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

      // 🔒 Block inactive users here (no LocalStrategy change needed)
      if (blockInactive(user)) {
        console.warn(`🚫 Inactive account attempted login: ${email}`);
        return res.status(403).render('member_form_views/error', {
          layout: 'memberformlayout',
          title: 'Account Inactive',
          errorMessage:
            'Your account is inactive. If this was a mistake, please contact support to reinstate your membership.',
        });
      }

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        console.warn(`❌ Password mismatch for ${email}`);
        return renderLoginError(res, req, 'Invalid email or password.');
      }

      // Normalize metadata for session + redirect
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

        // Lightweight session payload (consistent with the rest of the app)
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
};



