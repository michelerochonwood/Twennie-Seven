const express = require('express');
const router = express.Router();
const bytopicController = require('../../controllers/bytopicController');

// Route for viewing library units by topic
router.get('/:id', bytopicController.getTopicView);

module.exports = router;
