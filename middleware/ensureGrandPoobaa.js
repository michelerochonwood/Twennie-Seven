const ensureGrandPoobaa = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const adminEmail = process.env.GRAND_POOBAA_EMAIL;

  if (!adminEmail) {
    console.error(
      'GRAND_POOBAA_EMAIL is missing from the environment variables.'
    );

    return res.status(500).send(
      'Grand Poobaa access has not been configured.'
    );
  }

  const userEmail = String(req.user?.email || '')
    .trim()
    .toLowerCase();

  const allowedEmail = String(adminEmail)
    .trim()
    .toLowerCase();

  if (!userEmail || userEmail !== allowedEmail) {
    console.warn(
      `Unauthorized Grand Poobaa access attempt by user ${req.user?._id || 'unknown'}`
    );

    return res.status(403).send('You do not have permission to access this page.');
  }

  return next();
};

module.exports = ensureGrandPoobaa;