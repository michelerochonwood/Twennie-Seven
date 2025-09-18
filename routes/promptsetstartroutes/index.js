const express = require('express');
const router = express.Router();
const { startPromptSet } = require('../../controllers/startpromptsetController'); // or wherever you placed it

router.post('/start', startPromptSet);

module.exports = router;
