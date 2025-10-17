// middleware/access.js
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  const nextUrl = encodeURIComponent(req.originalUrl || '/dashboard');
  return res.redirect(`/auth/login?next=${nextUrl}`);
}

module.exports = { ensureLoggedIn };