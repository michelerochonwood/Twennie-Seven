const express = require('express');
const router = express.Router();

const unitSuggestionController = require('../../controllers/unitSuggestionController');

router.post('/org-suggestions/create', unitSuggestionController.create);

module.exports = router;