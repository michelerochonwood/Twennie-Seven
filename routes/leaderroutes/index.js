const express = require('express');
const router = express.Router();
const leaderController = require('../../controllers/leaderController');

// Simple auth guard (adjust to your auth logic)
function requireLeader(req, res, next) {
  if (!req.isAuthenticated?.() || req.user?.membershipType !== 'leader') {
    return res.redirect('/login');
  }
  next();
}

// Quick ObjectId validator
function validateObjectId(req, res, next) {
  const { leaderId } = req.params;
  if (!/^[0-9a-fA-F]{24}$/.test(leaderId)) {
    return res.status(400).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'Invalid leader ID.'
    });
  }
  next();
}

// Render leader form
router.get('/form', leaderController.showLeaderForm);

// Handle leader form submission
router.post('/form', leaderController.createLeader);

// Update members for all leaders (admin/internal)
router.post('/updateMembers', /* requireLeader, */ leaderController.updateMembers);

// Render the add group member form
router.get('/:leaderId/add_group_member', requireLeader, validateObjectId, leaderController.showAddGroupMemberForm);

// Handle add group member submission
router.post('/:leaderId/add_group_member', requireLeader, validateObjectId, leaderController.addGroupMember);

module.exports = router;
