const router = require('express').Router();

// GET /privacy/cookies – render cookie consent form
router.get('/cookies', (req, res) => {
  const csrfToken = typeof req.csrfToken === 'function' ? req.csrfToken() : null;
  return res.render('privacy_views/cookies', {
    layout: 'mainlayout',
    title: 'Cookie Preferences',
    csrfToken,
    currentConsent: res.locals.consent
  });
});

// POST /privacy/cookies – save consent cookie
router.post('/cookies', async (req, res) => {
  const { functional, analytics, marketing } = req.body || {}; // "on" or undefined

  const consent = {
    version: 1,
    necessary: true,
    functional: !!functional,
    analytics: !!analytics,
    marketing: !!marketing,
    updatedAt: new Date().toISOString()
  };

  res.cookie('twennieConsent', JSON.stringify(consent), {
    httpOnly: false, // client JS reads it to hide the banner
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: 1000 * 60 * 60 * 24 * 180, // 180 days
    path: '/',
    domain: process.env.COOKIE_DOMAIN || undefined // e.g. ".twennie.com" if you use apex + www
  });

  // (Optional) persist server-side for signed-in users:
  try {
    const u = req.session?.user;
    if (u?.id) {
      // TODO: update the correct model if you want an audit trail:
      // await Model.updateOne({ _id: u.id }, { $set: { cookieConsent: consent, cookieConsentUpdatedAt: new Date() } });
    }
  } catch {}

  return res.redirect('/privacy/cookies');
});

module.exports = router;



