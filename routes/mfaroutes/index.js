// routes/mfaroutes.js
const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bcrypt = require('bcrypt');

// Models
const Leader = require('../../models/member_models/leader');
const Member = require('../../models/member_models/member');
const GroupMember = require('../../models/member_models/group_member');

function roleToDashboard(role) {
  switch (role) {
    case 'leader':        return '/dashboard/leader';
    case 'group_member':  return '/dashboard/groupmember';
    default:              return '/dashboard/member';
  }
}

// CSRF helper
const setCsrf = (req, res, next) => {
  if (typeof req.csrfToken === 'function') {
    try { res.locals.csrfToken = req.csrfToken(); } catch (_) {}
  }
  next();
};

// Utils
const {
  encryptSecret,
  decryptSecret,
  generateRecoveryCodes,
  hashRecoveryCodes,
  verifyRecoveryCode,
} = require('../../utils/cryptoMfa');

// ---- helpers ----
const byRole = { leader: Leader, member: Member, group_member: GroupMember };

function isAuthenticated(req, res, next) {
  if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) return next();
  if (req.session?.user) { req.user = req.session.user; return next(); }
  return res.redirect('/auth/login');
}

async function getCurrentUserDoc(req) {
  const u = req.user || req.session?.user;
  if (!u) return null;
  const modelName = u?.constructor?.modelName;
  let Model, roleKey;
  if (modelName === 'Leader') { Model = Leader; roleKey = 'leader'; }
  else if (modelName === 'GroupMember') { Model = GroupMember; roleKey = 'group_member'; }
  else if (modelName === 'Member') { Model = Member; roleKey = 'member'; }
  else {
    const role = u.accessLevel || u.role;
    if (role === 'leader') { Model = Leader; roleKey = 'leader'; }
    else if (role === 'group_member') { Model = GroupMember; roleKey = 'group_member'; }
    else { Model = Member; roleKey = 'member'; }
  }
  const id = u._id?.toString?.() || u.id;
  if (!Model || !id) return null;
  const doc = modelName && u._id ? u : await Model.findById(id);
  return { doc, Model, role: roleKey };
}

function ctxBaseUrl(req) { return req.baseUrl || '/mfa'; }

/* =========================
   UI: MFA settings page
   ========================= */
// GET /mfa  (renders forms) -> needs CSRF
router.get('/', isAuthenticated, setCsrf, async (req, res) => {
  const ctx = await getCurrentUserDoc(req);
  if (!ctx || !ctx.doc) return res.redirect('/auth/login');
  return res.render('auth_views/mfa_settings', {
    layout: 'dashboardlayout',
    title: 'Multi-Factor Authentication',
    mfaEnabled: !!ctx.doc.mfa?.enabled,
    baseUrl: ctxBaseUrl(req),
  });
});

// Alias GET /mfa/settings  (renders forms) -> needs CSRF
router.get('/settings', isAuthenticated, setCsrf, async (req, res) => {
  const ctx = await getCurrentUserDoc(req);
  if (!ctx || !ctx.doc) return res.redirect('/auth/login');
  return res.render('auth_views/mfa_settings', {
    layout: 'dashboardlayout',
    title: 'Multi-Factor Authentication',
    mfaEnabled: !!ctx.doc.mfa?.enabled,
    baseUrl: ctxBaseUrl(req),
  });
});

/* ======================================================
   Step 1: Begin setup (generate secret + QR)
   POST /mfa/setup -> renders setup form -> needs CSRF
   ====================================================== */
router.post('/setup', isAuthenticated, setCsrf, async (req, res) => {
  const ctx = await getCurrentUserDoc(req);
  if (!ctx || !ctx.doc) return res.redirect('/auth/login');

  const labelName = `Twennie (${ctx.doc.username || ctx.doc.groupLeaderName || ctx.doc.name || 'user'})`;
  const secret = speakeasy.generateSecret({ name: labelName, issuer: 'Twennie', length: 20 });

  req.session.mfaSetup = { base32: secret.base32, otpauth_url: secret.otpauth_url };
  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

  return res.render('auth_views/mfa_setup', {
    layout: 'dashboardlayout',
    title: 'Set up MFA',
    qrDataUrl,
    manualKey: secret.base32,
    baseUrl: ctxBaseUrl(req),
  });
});

/* ======================================================
   Step 2: Verify setup token & save
   POST /mfa/verify-setup -> may re-render form -> include CSRF
   ====================================================== */
router.post('/verify-setup', isAuthenticated, setCsrf, async (req, res) => {
  const ctx = await getCurrentUserDoc(req);
  if (!ctx || !ctx.doc) return res.redirect('/auth/login');

  const userToken = (req.body?.token || '').trim();
  const setup = req.session.mfaSetup;

  if (!setup?.base32 || !userToken) {
    return res.status(400).render('member_form_views/error', {
      layout: 'mainlayout', title: 'Error', errorMessage: 'Invalid MFA setup session or token.',
    });
  }

  const ok = speakeasy.totp.verify({ secret: setup.base32, encoding: 'base32', token: userToken, window: 1 });

  if (!ok) {
    return res.render('auth_views/mfa_setup', {
      layout: 'dashboardlayout',
      title: 'Set up MFA',
      qrDataUrl: await qrcode.toDataURL(setup.otpauth_url),
      manualKey: setup.base32,
      error: 'Code did not match. Try again.',
      baseUrl: ctxBaseUrl(req),
    });
  }

  const enc = encryptSecret(setup.base32);
  const rawCodes = generateRecoveryCodes(10);
  const hashedCodes = await hashRecoveryCodes(rawCodes);

  ctx.doc.mfa = {
    enabled: true,
    method: 'totp',
    secretEnc: enc.secretEnc,
    secretIv: enc.secretIv,
    secretTag: enc.secretTag,
    recoveryCodes: hashedCodes,
    updatedAt: new Date(),
  };
  await ctx.doc.save();

  delete req.session.mfaSetup;

return res.render('auth_views/mfa_setup_success', {
  layout: 'dashboardlayout',
  title: 'MFA Enabled',
  recoveryCodes: rawCodes,
  dashboard: roleToDashboard(ctx.role),   // ← was '/dashboard/leader'
  baseUrl: ctxBaseUrl(req),
});
});

/* ===============================================
   Disable MFA (require a current code)
   POST /mfa/disable -> may re-render settings -> include CSRF
   =============================================== */
router.post('/disable', isAuthenticated, setCsrf, async (req, res) => {
  const ctx = await getCurrentUserDoc(req);
  if (!ctx || !ctx.doc || !ctx.doc.mfa?.enabled) return res.redirect('/auth/login');

  const token = (req.body?.token || '').trim();

  const secret = decryptSecret({
    secretEnc: ctx.doc.mfa.secretEnc,
    secretIv: ctx.doc.mfa.secretIv,
    secretTag: ctx.doc.mfa.secretTag,
  });

  const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

  if (!ok) {
    return res.render('auth_views/mfa_settings', {
      layout: 'dashboardlayout',
      title: 'Multi-Factor Authentication',
      mfaEnabled: true,
      error: 'Invalid MFA code. Try again.',
      baseUrl: ctxBaseUrl(req),
    });
  }

  ctx.doc.mfa = {
    enabled: false,
    method: undefined,
    secretEnc: undefined,
    secretIv: undefined,
    secretTag: undefined,
    recoveryCodes: [],
    updatedAt: new Date(),
  };
  await ctx.doc.save();

return res.render('auth_views/mfa_disable_success', {
  layout: 'dashboardlayout',
  title: 'MFA Disabled',
  dashboard: roleToDashboard(ctx.role),   // ← was '/dashboard/leader'
  baseUrl: ctxBaseUrl(req),
});
});

/* ======================================================
   Login challenge (after password)
   GET/POST /mfa/challenge
   ====================================================== */
// GET renders a form -> include CSRF
router.get('/challenge', setCsrf, async (req, res) => {
  if (
    (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) ||
    req.session?.pendingMfa?.userId
  ) {
    // ok
  } else {
    return res.redirect('/auth/login');
  }

  return res.render('auth_views/mfa_challenge', {
    layout: 'mainlayout',
    title: 'Verify MFA',
    baseUrl: ctxBaseUrl(req),
  });
});

router.post('/challenge', async (req, res) => {
  const pending = req.session?.pendingMfa;
  if (!pending?.userId || !pending?.role) return res.redirect('/auth/login');

  const Model = byRole[pending.role];
  const userDoc = await Model.findById(pending.userId);
  if (!userDoc || !userDoc.mfa?.enabled) {
    req.session.user = pending.user;
    delete req.session.pendingMfa;
    return res.redirect(pending.redirectTo || '/');
  }

  const token = (req.body?.token || '').trim();
  const secret = decryptSecret({
    secretEnc: userDoc.mfa.secretEnc,
    secretIv: userDoc.mfa.secretIv,
    secretTag: userDoc.mfa.secretTag,
  });

  let ok = false;
  if (token.includes('-')) {
    const idx = await verifyRecoveryCode(token.toUpperCase(), userDoc.mfa.recoveryCodes);
    if (idx >= 0) { ok = true; userDoc.mfa.recoveryCodes.splice(idx, 1); await userDoc.save(); }
  } else {
    ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  }

  if (!ok) {
    return res.render('auth_views/mfa_challenge', {
      layout: 'mainlayout',
      title: 'Verify MFA',
      error: 'Invalid code. Try again or use a recovery code.',
      baseUrl: ctxBaseUrl(req),
    });
  }

  req.session.user = pending.user;
  delete req.session.pendingMfa;

  return res.redirect(pending.redirectTo || '/');
});

module.exports = router;



