const express = require('express');
const router = express.Router();
const promptSetAssignController = require('../../controllers/promptsetassignController');
const isAuthenticated = require('../../middleware/ensureAuthenticated'); // Middleware to check authentication

// 🔹 Assign a prompt set to group members
router.post('/assign', isAuthenticated, promptSetAssignController.assignPromptSet);

// 🔹 Fetch assigned prompt sets for a leader
router.get('/assignments', isAuthenticated, promptSetAssignController.getAssignedPromptSets);

// 🔹 Fetch assigned prompt sets for a specific member
router.get('/assignments/me', isAuthenticated, promptSetAssignController.getAssignedPromptSetsForMember);

// 🔹 Unassign a prompt set (remove assignments)
router.delete('/unassign/:assignmentId', isAuthenticated, promptSetAssignController.unassignPromptSet);

// 🔹 Render success page after assigning a prompt set
router.get('/assignsuccess', (req, res) => {
    res.render('assignsuccess', {
        layout: 'unitviewlayout',
        promptset_title: req.query.title,
        frequency: req.query.frequency,  // ✅ Now passing `frequency`
        completion_date: req.query.completion_date,
        dashboard: req.query.dashboard
    });
});

module.exports = router;
