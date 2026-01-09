const express = require('express');
const router = express.Router();
const leaderController = require('../../controllers/leaderController');

// ------------------------------------------------------------
// Leader signup
// ------------------------------------------------------------

// Render leader form
router.get('/form', leaderController.showLeaderForm);

// Handle leader form submission
router.post('/form', leaderController.createLeader);

// Utility: update members for all leaders
router.post('/updateMembers', leaderController.updateMembers);


// ------------------------------------------------------------
// Organization (leader-owned)
// These match your embedded form action: POST /leader/organization
// ------------------------------------------------------------

// Create org from the register_success embedded partial
router.post('/organization', leaderController.createOrganization);

// Optional: edit org (for later)
router.get('/organization/edit', leaderController.showEditOrganizationForm);
router.post('/organization/edit', leaderController.updateOrganization);

router.get('/organization/success', (req, res) => {
  return res.redirect('/dashboard/leader/organization/success');
});


// ------------------------------------------------------------
// Group member management (specific leader)
// IMPORTANT: keep these AFTER /organization routes
// ------------------------------------------------------------

// Render add group member form
router.get('/:leaderId/add_group_member', leaderController.showAddGroupMemberForm);

// Handle add group member
router.post('/:leaderId/add_group_member', leaderController.addGroupMember);

// Success page after adding group member
router.get('/:leaderId/add_group_member/success', leaderController.showAddGroupMemberSuccess);

// Show delete group member page
router.get('/:leaderId/delete_group_member', leaderController.showDeleteGroupMemberForm);

// Handle delete
router.post('/:leaderId/delete_group_member', leaderController.deleteGroupMember);

module.exports = router;

