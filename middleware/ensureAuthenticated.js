// middleware/ensureAuthenticated.js

const ensureAuthenticated = (req, res, next) => {
  console.log('🔍 Middleware: Checking Authentication');
  console.log('   Session:', req.session);
  console.log('   req.isAuthenticated():', req.isAuthenticated && req.isAuthenticated());
  console.log('   req.user:', req.user);

  if (!req.user || !req.user._id) {
    console.warn('⚠️ req.user is missing or malformed. This will block access.');
  }

  // ✅ Restore req.user early if missing but session has it
  // IMPORTANT: Passport often stores only a user id in req.session.passport.user.
  // We must NOT assign that id directly to req.user.
  if (!req.user && req.session?.passport?.user) {
    console.warn('⚠️ Restoring user from session...');

    const sessionPassportUser = req.session.passport.user;

    // Only restore if it already looks like a full user object
    if (sessionPassportUser && typeof sessionPassportUser === 'object' && sessionPassportUser._id) {
      req.user = sessionPassportUser;
    } else {
      console.warn('⚠️ Session passport user looks like an id, not a full user object. Skipping restore.');
    }
  }

  // ✅ Proceed if user is now valid
  if (req.user && req.user._id) {
    console.log('✅ Authenticated user:', {
      id: req.user._id,
      membershipType: req.user.membershipType || 'Unknown Type',
      isAdmin: req.user.isAdmin
    });

    // ✅ Ensure session user is also present
    // Keep the original fields you rely on, plus admin/org flags when available
    if (!req.session.user) {
      console.warn('⚠️ Session user data is missing, restoring session...');
      req.session.user = {
        id: req.user._id,
        username: req.user.username,
        membershipType: req.user.membershipType
      };
    }

    // ✅ Keep admin/org flags fresh (won’t break if undefined)
    if (req.session.user) {
      if (typeof req.user.isAdmin !== 'undefined') req.session.user.isAdmin = !!req.user.isAdmin;
      if (typeof req.user.organization !== 'undefined') req.session.user.organization = req.user.organization || null;
      if (typeof req.user.organizationOptOut !== 'undefined') req.session.user.organizationOptOut = !!req.user.organizationOptOut;
    }

    return next();
  }

  // 🚨 Authentication failed
  console.warn('🚨 Access Denied: Not Authenticated or missing req.user._id.');
  return res.redirect('/auth/login');
};

module.exports = ensureAuthenticated;








