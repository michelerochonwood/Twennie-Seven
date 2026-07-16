const express = require('express');

const grandPoobaaController =
  require('../../controllers/grandpoobaaController');

const ensureGrandPoobaa =
  require('../../middleware/ensureGrandPoobaa');

const router = express.Router();


/**
 * ==========================================================
 * GRAND POOBAA DASHBOARD
 * ==========================================================
 */

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
 * ==========================================================
 * TOPIC SUGGESTIONS
 * ==========================================================
 */

/**
 * POST /grand-poobaa/topic-suggestions/:suggestionId/approve
 * Approve a topic suggestion.
 */
router.post(
  '/topic-suggestions/:suggestionId/approve',
  ensureGrandPoobaa,
  grandPoobaaController.approveTopicSuggestion
);


/**
 * ==========================================================
 * DEMO REQUESTS
 * ==========================================================
 */

/**
 * POST /grand-poobaa/demo-requests/:requestId/schedule
 * Mark a demo request as scheduled.
 */
router.post(
  '/demo-requests/:requestId/schedule',
  ensureGrandPoobaa,
  grandPoobaaController.scheduleDemoRequest
);


/**
 * POST /grand-poobaa/demo-requests/:requestId/complete
 * Mark a demo request as completed.
 */
router.post(
  '/demo-requests/:requestId/complete',
  ensureGrandPoobaa,
  grandPoobaaController.completeDemoRequest
);


/**
 * ==========================================================
 * LIBRARY UNIT APPROVAL
 * ==========================================================
 */

/**
 * POST /grand-poobaa/library-units/:unitId/approve
 * Approve a newly added library unit.
 *
 * The submitted form must also include the unitType so the
 * controller can determine which unit model contains the unit.
 */
router.post(
  '/library-units/:unitId/approve',
  ensureGrandPoobaa,
  grandPoobaaController.approveLibraryUnit
);


module.exports = router;