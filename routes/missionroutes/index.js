// File: routes/missionroutes/index.js

const express = require('express');
const router = express.Router();

const missionController = require('../../controllers/missionController');

// ------------------------------------------------------------
// Mission Control (landing page for all mission categories)
// Sidebar/Header link: <a href="/missioncontrol">
// ------------------------------------------------------------
router.get('/missioncontrol', missionController.missionControl);

// ------------------------------------------------------------
// Mission Category Pages
// These must match the view names in /views/unit_views/
// ------------------------------------------------------------

// Learning Missions
router.get(
  '/unitviews/missions/learning',
  missionController.learningMissions
);

// Research Missions
router.get(
  '/unitviews/missions/research',
  missionController.researchMissions
);

// Business Development Missions
router.get(
  '/unitviews/missions/businessdevelopment',
  missionController.businessDevelopmentMissions
);

// Internal Improvement Missions
router.get(
  '/unitviews/missions/internal_improvements',
  missionController.internalImprovementMissions
);

// Client Experience Missions
router.get(
  '/unitviews/missions/clientexperience',
  missionController.clientExperienceMissions
);

// Culture & Play Missions
router.get(
  '/unitviews/missions/cultureandplay',
  missionController.cultureAndPlayMissions
);

router.get(
  '/unitviews/missions/community',
  missionController.communityMissions
);

// Administrative Missions
router.get(
  '/unitviews/missions/administrative',
  missionController.administrativeMissions
);

// Rogue Missions (schema category = 'other')
router.get(
  '/unitviews/missions/rogue',
  missionController.rogueMissions
);

// ------------------------------------------------------------
// Single Mission View
// CTA in cards: href="/unitviews/missions/view/{{_id}}"
// ------------------------------------------------------------
router.get(
  '/unitviews/missions/view/:id',
  missionController.viewMission
);



module.exports = router;
