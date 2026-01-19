// middleware/ensureCanContribute.js
// Low-risk: no DB queries, no async, no mutations.

const ALLOWED_MEMBER_LEVELS = new Set(['paid_individual', 'contributor_individual']);

module.exports = function ensureCanContribute(req, res, next) {
  const u = req.user;
  const sessionUser = req.session?.user;

  // If ensureAuthenticated ran, u should exist, but keep this safe.
  if (!u || !u._id) return res.redirect('/auth/login');

  // ✅ Leaders: allow
  // (Leader docs typically have groupLeaderEmail; membershipType may be undefined)
  if (u.groupLeaderEmail || u.membershipType === 'leader') return next();

  // ✅ Group members: allow
  if (u.membershipType === 'group_member') return next();

  // ✅ Individual members: only paid + contributor
  if (u.membershipType === 'member') {
    const level = u.accessLevel || sessionUser?.accessLevel; // session fallback if you ever add it
    if (ALLOWED_MEMBER_LEVELS.has(level)) return next();
    return res.redirect('/membership');
  }

  // Default deny
  return res.redirect('/membership');
};
