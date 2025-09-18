const express = require('express');
const router = express.Router();
const changeMembershipController = require('../../controllers/changemembershipController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// Show membership change interface
router.get('/', ensureAuthenticated, changeMembershipController.showChangeMembershipForm);

// Membership change success confirmation
router.get('/success', ensureAuthenticated, changeMembershipController.changeSuccess);

// Membership cancellations
router.post('/cancel', ensureAuthenticated, changeMembershipController.cancelMembership);

// Change to free individual membership
router.post('/free', ensureAuthenticated, changeMembershipController.changeToFree);

// Change to paid individual membership (with Stripe redirect)
router.post('/individual', ensureAuthenticated, changeMembershipController.changeToIndividual);



// ✅ POST: Handle membership change to leader
router.post('/leader', ensureAuthenticated, changeMembershipController.changeToLeader);

module.exports = router;


