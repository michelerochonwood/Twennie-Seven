const express = require('express');
const router = express.Router();
const { startPromptSet } = require('../../controllers/startpromptsetController');

// Use the same minimal gate used by your dashboards
const isAuthenticated = (req, res, next) => {
  if (req.session?.user) {
    console.log(`User authenticated: ${req.session.user.username}`);
    return next();
  }
  console.warn('Access denied. Redirecting to login.');
  return res.redirect('/auth/login');
};

router.post('/start', isAuthenticated, startPromptSet);

module.exports = router;
