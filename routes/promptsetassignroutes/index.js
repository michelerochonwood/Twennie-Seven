// routes/promptsetassign.js
const express = require('express');
const router = express.Router();

const promptSetAssignController = require('../../controllers/promptsetassignController');
const isAuthenticated = require('../../middleware/ensureAuthenticated'); // auth gate

// Assign a prompt set to group members (fan-out happens in controller)
router.post('/assign', isAuthenticated, promptSetAssignController.assignPromptSet);

// Fetch assigned prompt sets for a leader
router.get('/assignments', isAuthenticated, promptSetAssignController.getAssignedPromptSets);

// Fetch assigned prompt sets for the current member
router.get('/assignments/me', isAuthenticated, promptSetAssignController.getAssignedPromptSetsForMember);

// ✅ Unassign a single member (more specific route FIRST)
router.delete(
  '/unassign/:assignmentId/:memberId',
  isAuthenticated,
  promptSetAssignController.unassignPromptSetMember
);

// Unassign a prompt set (remove a single assignment doc)
router.delete(
  '/unassign/:assignmentId',
  isAuthenticated,
  promptSetAssignController.unassignPromptSet
);

// Render success page after assigning a prompt set
// (Reads one-time summary from req.session.lastAssignSummary and clears it)
router.get('/assignsuccess', isAuthenticated, (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  return promptSetAssignController.assignSuccess(req, res, next);
});

module.exports = router;



