const express = require('express');
const router = express.Router();
const latestController = require('../../controllers/latestController');

// Route to display latest library items
router.get('/', latestController.getLatestLibraryItems);

module.exports = router;
