// middleware/ensureCanContribute.js
// Low-risk: no DB queries, no async, no mutations.

const ALLOWED_MEMBER_LEVELS = new Set(['paid_individual', 'contributor_individual']);

module.exports = function ensureCanContribute(req, res, next) {
  const u = req.user;
  const sessionUser = req.session?.user;

  if (!u || !u._id) return res.redirect('/auth/login');

  // ✅ Infer membership type if missing
  const type =
    u.membershipType ||
    sessionUser?.membershipType ||
    (u.groupLeaderEmail ? 'leader' : null) ||
    (u.email ? 'member' : null);

  // ✅ Leaders: allow
  if (type === 'leader' || u.groupLeaderEmail) return next();

  // ✅ Group members: allow
  if (type === 'group_member') return next();

  // ✅ Members: only paid + contributor
  if (type === 'member') {
    const level = u.accessLevel || sessionUser?.accessLevel;
    if (ALLOWED_MEMBER_LEVELS.has(level)) return next();
    return res.redirect('/membership');
  }

  return res.redirect('/membership');
};

