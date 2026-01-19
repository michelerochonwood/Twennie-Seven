// middleware/ensureCanContribute.js
// Low-risk: no DB queries, no async, no mutations.

const ALLOWED_MEMBER_LEVELS = new Set(['paid_individual', 'contributor_individual']);

console.log('[ensureCanContribute]', {
  path: req.originalUrl,
  hasUser: !!u,
  userId: u?._id?.toString?.() || u?._id,
  membershipType: u?.membershipType,
  hasGroupLeaderEmail: !!u?.groupLeaderEmail,
  hasEmail: !!u?.email,
  accessLevel: u?.accessLevel,
  sessionUser: req.session?.user ? {
    id: req.session.user.id,
    membershipType: req.session.user.membershipType,
    accessLevel: req.session.user.accessLevel,
    username: req.session.user.username
  } : null,
  passportSession: req.session?.passport?.user || null
});


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

