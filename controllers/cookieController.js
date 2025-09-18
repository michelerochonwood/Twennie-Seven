// controllers/cookieController.js
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

// controllers/cookieController.js
function writeUiCookieIfAllowed(req, res, prefs) {
  try {
    const consent = req.cookies.twennieConsent ? JSON.parse(req.cookies.twennieConsent) : {};
    if (consent.functional) {
      res.cookie('tw_ui', JSON.stringify({
        tab: prefs.defaultDashboardTab ?? 'membership',
        reducedMotion: !!prefs.reducedMotion,
        density: prefs.contentDensity ?? 'comfortable'
      }), {
        maxAge: 1000 * 60 * 60 * 24 * 180,
        sameSite: 'Lax',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: false,
        domain: process.env.COOKIE_DOMAIN || undefined,
        path: '/'
      });
    }
  } catch {}
}

function getPrefsPayload(body = {}) {
  return {
    'preferences.defaultDashboardTab': body.defaultDashboardTab || 'membership',
    'preferences.reducedMotion': !!body.reducedMotion,
    'preferences.contentDensity': body.contentDensity || 'comfortable'
  };
}


exports.updateMemberPreferences = async (req, res) => {
  const id = req.session?.user?.id || req.user?._id?.toString();
  if (!id) return res.redirect('/auth/login');

  const updates = getPrefsPayload(req.body);
  await Member.findByIdAndUpdate(id, { $set: updates });

  writeUiCookieIfAllowed(req, res, {
    theme: req.body.theme,
    defaultDashboardTab: req.body.defaultDashboardTab,
    reducedMotion: !!req.body.reducedMotion,
    contentDensity: req.body.contentDensity
  });

  return res.redirect('/dashboard/member');
};

exports.updateLeaderPreferences = async (req, res) => {
  const id = req.session?.user?.id || req.user?._id?.toString();
  if (!id) return res.redirect('/auth/login');

  const updates = getPrefsPayload(req.body);
  await Leader.findByIdAndUpdate(id, { $set: updates });

  writeUiCookieIfAllowed(req, res, {
    theme: req.body.theme,
    defaultDashboardTab: req.body.defaultDashboardTab,
    reducedMotion: !!req.body.reducedMotion,
    contentDensity: req.body.contentDensity
  });

  return res.redirect('/dashboard/leader');
};

exports.updateGroupMemberPreferences = async (req, res) => {
  const id = req.session?.user?.id || req.user?._id?.toString();
  if (!id) return res.redirect('/auth/login');

  const updates = getPrefsPayload(req.body);
  await GroupMember.findByIdAndUpdate(id, { $set: updates });

  writeUiCookieIfAllowed(req, res, {
    theme: req.body.theme,
    defaultDashboardTab: req.body.defaultDashboardTab,
    reducedMotion: !!req.body.reducedMotion,
    contentDensity: req.body.contentDensity
  });

  return res.redirect('/dashboard/groupmember');
};
