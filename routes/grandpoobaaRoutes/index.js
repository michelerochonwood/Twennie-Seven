const express = require('express');

const grandPoobaaController = require('../controllers/grandpoobaaController');
const ensureGrandPoobaa = require('../middleware/ensureGrandPoobaa');

const router = express.Router();

/**
 * GET /grand-poobaa
 * Main Twennie administrative dashboard.
 */
router.get(
  '/',
  ensureGrandPoobaa,
  grandPoobaaController.showDashboard
);

module.exports = router;