const express = require('express');
const router = express.Router();
const promptsetcompleteController = require('../../controllers/promptsetcompletionController');

// API Route: Fetch all completed prompt sets for a member
router.get('/completed/:memberId', promptsetcompleteController.getCompletedPromptSets);

// Route for rendering the completion success page
router.get('/success', promptsetcompleteController.promptsetCompleteSuccess);

module.exports = router;

