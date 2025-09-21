// routes/api/tagRoutes.js
const express = require('express');
const router = express.Router();

const tagController = require('../../controllers/tagController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

/**
 * Tag routes
 *
 * Legend:
 * - createTag                POST   /tags/create
 * - getTagsForItem           GET    /tags/item/:itemId/:itemType
 * - getTagsForUser           GET    /tags/user
 * - removeTag (detach)       DELETE /tags/remove/:tagId/:itemId/:itemType
 * - completeAssignment       PATCH  /tags/:tagId/complete
 * - unassignMember           DELETE /tags/:tagId/assigned/:memberId
 * - getAssignedToMe          GET    /tags/assigned-to-me
 * - deleteTag (entire doc)   DELETE /tags/:tagId
 */

// --- Tag Creation & Fetching ---

// Create a new tag (self-tag or leader assignment)
// Requires login
router.post('/create', ensureAuthenticated, tagController.createTag);

// Get all tags for a specific unit or topic
// Public (useful for rendering unit pages)
router.get('/item/:itemId/:itemType', tagController.getTagsForItem);

// Get all tags created by the logged-in user (for dashboards)
// Requires login
router.get('/user', ensureAuthenticated, tagController.getTagsForUser);

// --- Tag Removal (detach from a single unit/topic) ---

// Remove a tag from a unit or topic (creator-only enforced in controller)
// Requires login
router.delete('/remove/:tagId/:itemId/:itemType', ensureAuthenticated, tagController.removeTag);

// --- Assignment Lifecycle ---

// Group member marks their own assignment complete
// Requires login
router.patch('/:tagId/complete', ensureAuthenticated, tagController.completeAssignment);

// Leader unassigns a member from a tag (creator-only enforced in controller)
// Requires login
router.delete('/:tagId/assigned/:memberId', ensureAuthenticated, tagController.unassignMember);

// Group member fetches tags assigned to them (their "inbox")
// Requires login
router.get('/assigned-to-me', ensureAuthenticated, tagController.getAssignedToMe);

// --- Full Tag Delete (remove the entire tag document everywhere) ---

// Delete entire tag (creator-only enforced in controller)
// Requires login
// NOTE: Placed after the more specific '/assigned' and '/remove' routes
router.delete('/:tagId', ensureAuthenticated, tagController.deleteTag);

module.exports = router;


