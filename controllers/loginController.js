// controllers/loginController.js
const bcrypt = require('bcrypt');
const passport = require('passport');

const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const crypto = require('crypto');
const PasswordResetToken = require('../models/member_models/password_reset_token');
const { sendMail } = require('../utils/mailer');

function renderLoginError(res, req, msg) {
  return res.status(401).render('login_views/login_view', {
    layout: 'mainlayout',
    title: 'Login',
    error: msg,
    csrfToken: req.csrfToken ? req.csrfToken() : null,
  });
}

async function findUserWithTypeByEmail(emailLower) {
  const member = await Member.findOne({ email: emailLower });
  if (member) return { user: member, userType: 'member', email: member.email };

  const leader = await Leader.findOne({ groupLeaderEmail: emailLower });
  if (leader) return { user: leader, userType: 'leader', email: leader.groupLeaderEmail };

  const gm = await GroupMember.findOne({ email: emailLower });
  if (gm) return { user: gm, userType: 'group_member', email: gm.email };

  return { user: null, userType: null, email: null };
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
  const csrfToken = req.csrfToken ? req.csrfToken() : null;

  let error = null;
  if (req.query.error === 'google') {
    error = 'No Twennie account found for that Google email. Please sign up or use your email and password.';
  }

  res.render('login_views/login_view', {
    layout: 'mainlayout',
    title: 'Login',
    csrfToken,
    error
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

  // GET /auth/forgot-password
showForgotPasswordForm: (req, res) => {
  return res.render('login_views/forgot_password', {
    layout: 'mainlayout',
    title: 'Forgot Password',
    csrfToken: req.csrfToken ? req.csrfToken() : null,
  });
},

// POST /auth/forgot-password
requestPasswordReset: async (req, res) => {
  const csrfToken = req.csrfToken ? req.csrfToken() : null;
  const email = (req.body.email || '').toLowerCase().trim();

  // Always show same response (prevents email enumeration)
  const genericMsg = 'If an account exists for that email, we sent a reset link. Please check your inbox.';

  try {
    if (!email) {
      return res.status(400).render('login_views/forgot_password', {
        layout: 'mainlayout',
        title: 'Forgot Password',
        csrfToken,
        error: 'Please enter your email address.'
      });
    }

    const { user, userType, email: normalizedEmail } = await findUserWithTypeByEmail(email);

    // Render success even if not found (security)
    if (!user) {
      return res.render('login_views/forgot_password', {
        layout: 'mainlayout',
        title: 'Forgot Password',
        csrfToken,
        message: genericMsg
      });
    }

    // Block inactive users (optional)
    if (user.isActive === false) {
      return res.render('login_views/forgot_password', {
        layout: 'mainlayout',
        title: 'Forgot Password',
        csrfToken,
        message: genericMsg
      });
    }

    // Generate token (store only a hash)
    const tokenPlain = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(tokenPlain).digest('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Invalidate old unused tokens for this user
    await PasswordResetToken.updateMany(
      { userId: user._id, userType, usedAt: null },
      { $set: { usedAt: new Date() } }
    );

    await PasswordResetToken.create({
      userId: user._id,
      userType,
      tokenHash,
      expiresAt
    });

    const baseUrl = process.env.BASE_URL || 'https://www.twennie.com';
    const resetUrl = `${baseUrl}/auth/reset-password?token=${encodeURIComponent(tokenPlain)}`;

    await sendMail({
      to: normalizedEmail,
      subject: 'Reset your Twennie password',
      text: `Reset your password: ${resetUrl}\n\nThis link expires in 1 hour.`,
      html: `
        <p>Hi!</p>
        <p>We received a request to reset your Twennie password.</p>
        <p><a href="${resetUrl}">Click here to reset your password</a> (expires in 1 hour).</p>
        <p>If you didn’t request this, you can ignore this email.</p>
      `
    });

    return res.render('login_views/forgot_password', {
      layout: 'mainlayout',
      title: 'Forgot Password',
      csrfToken,
      message: genericMsg
    });
  } catch (err) {
    console.error('❌ requestPasswordReset error:', err);
    // Still show generic message
    return res.render('login_views/forgot_password', {
      layout: 'mainlayout',
      title: 'Forgot Password',
      csrfToken,
      message: genericMsg
    });
  }
},

// GET /auth/reset-password?token=...
showResetPasswordForm: async (req, res) => {
  const csrfToken = req.csrfToken ? req.csrfToken() : null;
  const tokenPlain = String(req.query.token || '');
console.log("➡️ GET /auth/forgot-password hit");
  if (!tokenPlain) {
    return res.status(400).render('login_views/login_view', {
      layout: 'mainlayout',
      title: 'Login',
      csrfToken,
      error: 'Reset link is invalid. Please request a new one.'
    });
  }

  return res.render('login_views/reset_password', {
    layout: 'mainlayout',
    title: 'Reset Password',
    csrfToken,
    token: tokenPlain
  });
},

// POST /auth/reset-password
handleResetPassword: async (req, res) => {
  const csrfToken = req.csrfToken ? req.csrfToken() : null;
  const tokenPlain = (req.body.token || '').trim();
  const password = req.body.password || '';
  const confirmPassword = req.body.confirmPassword || '';

  try {
    if (!tokenPlain) {
      return res.status(400).render('login_views/login_view', {
        layout: 'mainlayout',
        title: 'Login',
        csrfToken,
        error: 'Reset link is invalid. Please request a new one.'
      });
    }

    if (password.length < 8) {
      return res.status(400).render('login_views/reset_password_view', {
        layout: 'mainlayout',
        title: 'Reset Password',
        csrfToken,
        token: tokenPlain,
        error: 'Password must be at least 8 characters.'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).render('login_views/reset_password_view', {
        layout: 'mainlayout',
        title: 'Reset Password',
        csrfToken,
        token: tokenPlain,
        error: 'Passwords do not match.'
      });
    }

    const tokenHash = crypto.createHash('sha256').update(tokenPlain).digest('hex');

    const record = await PasswordResetToken.findOne({
      tokenHash,
      usedAt: null,
      expiresAt: { $gt: new Date() }
    });

    if (!record) {
      return res.status(400).render('login_views/login_view', {
        layout: 'mainlayout',
        title: 'Login',
        csrfToken,
        error: 'That reset link has expired or is invalid. Please request a new one.'
      });
    }

    // Load the user from the correct collection
    let user = null;
    if (record.userType === 'member') user = await Member.findById(record.userId);
    else if (record.userType === 'leader') user = await Leader.findById(record.userId);
    else user = await GroupMember.findById(record.userId);

    if (!user) {
      await PasswordResetToken.updateOne({ _id: record._id }, { $set: { usedAt: new Date() } });
      return res.status(400).render('login_views/login_view', {
        layout: 'mainlayout',
        title: 'Login',
        csrfToken,
        error: 'That reset link is invalid. Please request a new one.'
      });
    }

    // Hash + save
    const hashed = await bcrypt.hash(password, 12);
    user.password = hashed;
    await user.save();

    // Mark token used
    await PasswordResetToken.updateOne({ _id: record._id }, { $set: { usedAt: new Date() } });

    return res.render('login_views/login_view', {
      layout: 'mainlayout',
      title: 'Login',
      csrfToken,
      message: 'Password updated. You can log in now.'
    });
  } catch (err) {
    console.error('❌ handleResetPassword error:', err);
    return res.status(500).render('login_views/login_view', {
      layout: 'mainlayout',
      title: 'Login',
      csrfToken,
      error: 'We could not reset your password. Please try again.'
    });
  }
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




