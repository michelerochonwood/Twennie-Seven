const express = require('express');
const router = express.Router();
const { startPromptSet } = require('../../controllers/startpromptsetController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

router.post('/start', ensureAuthenticated, startPromptSet);

module.exports = router;
