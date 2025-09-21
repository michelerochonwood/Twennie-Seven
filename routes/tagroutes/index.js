// routes/api/tagRoutes.js
const express = require('express');
const router = express.Router();
const tagController = require('../../controllers/tagController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// --- Tag Creation & Fetching ---

// Create a new tag (self-tags or leader assigning)
// Requires login
router.post('/create', ensureAuthenticated, tagController.createTag);

// Get all tags for a specific unit or topic
// Public: e.g. for rendering unit pages
router.get('/item/:itemId/:itemType', tagController.getTagsForItem);

// Get all tags created by the logged-in user (for dashboard)
router.get('/user', ensureAuthenticated, tagController.getTagsForUser);

// --- Tag Removal ---

// Remove a tag from a unit or topic
// Requires login; group members can only remove their own
router.delete('/remove/:tagId/:itemId/:itemType', ensureAuthenticated, tagController.removeTag);

// --- Assignment Lifecycle ---

// Group member marks their own assignment complete
router.patch('/:tagId/complete', ensureAuthenticated, tagController.completeAssignment);

// Leader unassigns a member from a tag
router.delete('/:tagId/assigned/:memberId', ensureAuthenticated, tagController.unassignMember);

// Group member fetches tags assigned to them (their "inbox")
router.get('/assigned-to-me', ensureAuthenticated, tagController.getAssignedToMe);

module.exports = router;

