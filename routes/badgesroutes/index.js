const express = require('express');
const router = express.Router();
const csrf = require('csurf');
const badgesController = require('../../controllers/badgesController');

const csrfProtection = csrf();

// Route to view badges (CSRF protected for form tokens)
router.get('/', csrfProtection, badgesController.showBadgesView);

// Route to pick a badge (NO CSRF protection needed for AJAX fetch)
router.post('/pick', badgesController.pickBadge);

module.exports = router;




