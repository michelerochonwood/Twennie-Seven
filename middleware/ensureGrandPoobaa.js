const ensureGrandPoobaa = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/auth/login');
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

  const userEmail = String(
    req.user?.email ||
    req.user?.username ||
    ''
  )
    .trim()
    .toLowerCase();

  const allowedEmail = String(adminEmail)
    .trim()
    .toLowerCase();

  if (!userEmail || userEmail !== allowedEmail) {
    console.warn('Unauthorized Grand Poobaa access attempt:', {
      userId: req.user?._id || 'unknown',
      userEmail,
      allowedEmail
    });

    return res
      .status(403)
      .send('You do not have permission to access this page.');
  }

  return next();
};

module.exports = ensureGrandPoobaa;