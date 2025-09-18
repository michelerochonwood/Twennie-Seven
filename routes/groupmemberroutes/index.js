const express = require('express');
const router = express.Router();
const groupmemberController = require('../../controllers/groupmemberController');

// ✅ Render the verification form (loads the group selection page)
router.get('/verify', groupmemberController.showVerifyMemberForm);

// ✅ Verify the registration code (used only to reveal group members)
router.post('/verify-registration-code', groupmemberController.verifyRegistrationCode);

// ✅ Redirect to the complete registration form instead of a POST request
router.get("/complete-registration", groupmemberController.showCompleteMemberForm);


// ✅ Register a group member (final registration step)
router.post('/register', groupmemberController.registerGroupMember);

module.exports = router;

