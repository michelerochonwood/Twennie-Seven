const express = require('express');
const router = express.Router();

const unitSuggestionController = require('../../controllers/unitsuggestionController');

router.post('/org-suggestions/create', unitSuggestionController.create);

module.exports = router;