// routes/archiveRoutes.js
const express = require('express');
const router = express.Router();
const archiveController = require('../controllers/archiveController');

router.post('/archive', archiveController.archiveUnit);

module.exports = router;