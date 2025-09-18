const express = require('express');
const router = express.Router();
const tagController = require('../../controllers/tagController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// Create a new tag
router.post('/create', tagController.createTag);

// Get all tags for a specific unit or topic
router.get('/item/:itemId/:itemType', tagController.getTagsForItem);

// Get all tags created by the logged-in user (for dashboard)
router.get('/user', tagController.getTagsForUser);

// Remove a tag from a unit or topic
router.delete('/remove/:tagId/:itemId/:itemType', ensureAuthenticated, tagController.removeTag);


module.exports = router;

