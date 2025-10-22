const express = require('express');
const router = express.Router();
const promptSetAssignController = require('../../controllers/promptsetassignController');
const isAuthenticated = require('../../middleware/ensureAuthenticated'); // Middleware to check authentication

// 🔹 Assign a prompt set to group members (fan-out happens in controller)
router.post('/assign', isAuthenticated, promptSetAssignController.assignPromptSet);

// 🔹 Fetch assigned prompt sets for a leader
router.get('/assignments', isAuthenticated, promptSetAssignController.getAssignedPromptSets);

// 🔹 Fetch assigned prompt sets for a specific member
router.get('/assignments/me', isAuthenticated, promptSetAssignController.getAssignedPromptSetsForMember);

// 🔹 Unassign a prompt set (remove a single assignment doc)
router.delete('/unassign/:assignmentId', isAuthenticated, promptSetAssignController.unassignPromptSet);

// 🔹 Render success page after assigning a prompt set
router.get('/assignsuccess', isAuthenticated, (req, res) => {
  // Prefer the one-time session payload set by the controller; fall back to query params
  const sessionData = req.session.lastAssignSummary || null;

  const viewData = {
    layout: 'unitviewlayout',

    // Title & meta
    promptSetTitle: sessionData?.promptSetTitle || req.query.title || '',
    frequency: req.query.frequency || '',
    completion_date: req.query.completion_date || '',
    dashboard: req.query.dashboard || '/dashboard/leader',

    // Names (assigned / skipped)
    assignedNames: sessionData?.assignedNames || [],
    skippedLimitNames: sessionData?.skippedLimitNames || [],
    skippedDupesNames: sessionData?.skippedDupesNames || []
  };

  // Clear one-time summary after read
  if (req.session.lastAssignSummary) {
    delete req.session.lastAssignSummary;
  }

  return res.render('assignsuccess', viewData);
});

module.exports = router;

