const express = require('express');
const passport = require('passport');
const router = express.Router();
const loginController = require('../../controllers/loginController');

// Route to render the login page
router.get('/login', loginController.showLoginForm);

// Route to handle local login submission
router.post('/login', loginController.handleLogin);

// Route to handle logout
router.get('/logout', loginController.handleLogout);

// =====================
// Google Authentication Routes
// =====================

// Route to initiate Google authentication
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback route after Google login
router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/dashboard'); // Redirect to the desired page after successful login
    }
);

module.exports = router;

