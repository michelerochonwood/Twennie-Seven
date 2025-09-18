const router = require('express').Router();

// helper to read existing UI cookie for prefilling the form
function readUiCookie(req) {
  try { return req.cookies.tw_ui ? JSON.parse(req.cookies.tw_ui) : {}; }
  catch { return {}; }
}

// GET /ui/preferences – public UI preferences (no login required)
router.get('/preferences', (req, res) => {
  const csrfToken = typeof req.csrfToken === 'function' ? req.csrfToken() : null;
  const ui = readUiCookie(req);
  return res.render('preference_views/ui', {
    layout: 'mainlayout',
    title: 'Site Preferences',
    csrfToken,
    uiPrefsFromCookie: ui
  });
});

// POST /ui/preferences – write the tw_ui cookie (no DB)
router.post('/preferences', (req, res) => {
  // Only the fields you’re currently using (no theme)
  const ui = {
    tab: req.body.defaultDashboardTab || 'membership',
    reducedMotion: !!req.body.reducedMotion,
    density: req.body.contentDensity || 'comfortable'
  };

  // Only write if Functional cookies are allowed
  try {
    const consent = req.cookies.twennieConsent ? JSON.parse(req.cookies.twennieConsent) : {};
    if (consent.functional) {
      res.cookie('tw_ui', JSON.stringify(ui), {
        maxAge: 1000 * 60 * 60 * 24 * 180, // 180 days
        sameSite: 'Lax',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: false, // client uses it for instant UX
        domain: process.env.COOKIE_DOMAIN || undefined,
        path: '/'
      });
    }
  } catch {}

  return res.redirect(req.get('referer') || '/');
});

module.exports = router;



