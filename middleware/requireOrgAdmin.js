// middleware/requireOrgAdmin.js
const requireOrgAdmin = (req, res, next) => {
  // This middleware should be used AFTER ensureAuthenticated
  // so req.user should exist here.
  if (!req.user || !req.user._id) {
    console.warn('🚨 requireOrgAdmin: req.user missing. Did you forget ensureAuthenticated?');
    return res.redirect('/auth/login');
  }

  // Must be a leader
  const isLeader =
    req.user.membershipType === 'leader' ||
    req.user.accessLevel === 'leader';

  if (!isLeader) {
    console.warn('🚫 requireOrgAdmin: user is not a leader', {
      id: req.user._id,
      membershipType: req.user.membershipType,
      accessLevel: req.user.accessLevel
    });
    return res.redirect('/dashboard'); // or wherever non-leaders land
  }

  // Must belong to an organization AND not be opted out
  if (req.user.organizationOptOut === true) {
    console.warn('🚫 requireOrgAdmin: leader opted out of organization', { id: req.user._id });
    return res.redirect('/dashboard/leader'); // safe fallback
  }

  if (!req.user.organization) {
    console.warn('🚫 requireOrgAdmin: leader has no organization linked', { id: req.user._id });
    return res.redirect('/dashboard/leader'); // safe fallback
  }

  // Must be an admin
  if (req.user.isAdmin !== true) {
    console.warn('🚫 requireOrgAdmin: leader is not an org admin', { id: req.user._id });
    return res.redirect('/dashboard/leader');
  }

  return next();
};

module.exports = requireOrgAdmin;

