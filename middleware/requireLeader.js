// middleware/requireLeader.js
module.exports = function requireLeader(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).render('auth/login', {
        error: 'Please log in to continue.'
      });
    }

    const isLeader =
      req.user.accessLevel === 'leader' ||
      req.user.membershipType === 'leader';

    if (!isLeader) {
      return res.status(403).render('errors/403', {
        error: 'Leader access required.'
      });
    }

    return next();
  } catch (err) {
    return next(err);
  }
};
