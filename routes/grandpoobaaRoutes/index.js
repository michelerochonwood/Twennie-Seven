const express = require('express');

const grandPoobaaController =
  require('../../controllers/grandpoobaaController');

const ensureGrandPoobaa =
  require('../../middleware/ensureGrandPoobaa');

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


/**
 * POST /grand-poobaa/topic-suggestions/:suggestionId/approve
 * Approve a topic suggestion.
 */
router.post(
  '/topic-suggestions/:suggestionId/approve',
  ensureGrandPoobaa,
  grandPoobaaController.approveTopicSuggestion
);


module.exports = router;