const express = require('express');
const router = express.Router();
const leaderController = require('../../controllers/leaderController');

// Route to render leader form
router.get('/form', leaderController.showLeaderForm);

// Route to handle leader form submission
router.post('/form', leaderController.createLeader);

// Route to update members for all leaders
router.post('/updateMembers', leaderController.updateMembers);

// Route to render the add group member form for a specific leader by ID
router.get('/:leaderId/add_group_member', leaderController.showAddGroupMemberForm);

// Route to handle group member addition for a specific leader by ID
router.post('/:leaderId/add_group_member', leaderController.addGroupMember);

module.exports = router;
