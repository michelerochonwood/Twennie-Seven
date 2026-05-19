// File: routes/unitviewroutes/index.js
const express = require('express');
const router = express.Router();
const unitviewController = require('../../controllers/unitviewController');
const missionController = require('../../controllers/missionController');


// Lightweight auth gate for JSON POSTs (views themselves remain open;
// controller enforces visibility rules)
const isAuthenticated = (req, res, next) => {
  if (req.user) return next();
  return res.status(401).json({ error: 'Not authenticated' });
};

// ----- unit views (existing) -----
router.get('/articles/view/:id', unitviewController.viewArticle);
router.get('/videos/view/:id', unitviewController.viewVideo);
router.get('/interviews/view/:id', unitviewController.viewInterview);
router.get('/promptsets/view/:id', unitviewController.viewPromptset);
router.get('/exercises/view/:id', unitviewController.viewExercise);
router.get('/templates/view/:id', unitviewController.viewTemplate);
router.get('/missions/view/:id', unitviewController.viewMission);


router.get(
  '/templates/:templateId/download/:fileRole',
  isAuthenticated,
  unitviewController.downloadTemplateFile
);
// ----- The Mine (section root and landing) -----
// Visiting /unitviews will bounce to the Mine landing for convenience
router.get('/', (req, res) => res.redirect('/unitviews/mine'));

// Uses the single mine_list.hbs to show three category tiles
router.get('/mine', (req, res) => {
  console.log('[unitviewroutes] GET /unitviews/mine');
  return res.render('unit_views/mine_list', {
    layout: 'unitviewlayout',
    listTitle: 'Welcome to the Twennie Mine',
    listSubtitle: 'Choose a path to explore Nuggets by Client, Region, or Discipline.',
    items: [
      { label: 'client', href: '/unitviews/mine/clients' },
      { label: 'region', href: '/unitviews/mine/regions' },
      { label: 'discipline', href: '/unitviews/mine/disciplines' },
    ],
    itemType: 'category'
  });
});

// ----- The Mine (lists managed by controller) -----
// Effective URLs (because of /unitviews mount):
//   /unitviews/mine/clients
//   /unitviews/mine/regions
//   /unitviews/mine/disciplines
router.get('/mine/clients', (req, res, next) => {
  console.log('[unitviewroutes] -> /unitviews/mine/clients (calling viewMineClients)');
  return unitviewController.viewMineClients(req, res, next);
});

router.get('/mine/regions', unitviewController.viewMineRegions);
router.get('/mine/disciplines', unitviewController.viewMineDisciplines);

// ----- nuggets -----
router.get('/nuggets/view/:id', unitviewController.viewNugget);

// ----- upcoming unit -----
router.get('/upcoming/view/:id', unitviewController.viewUpcoming);

// ----- notes success (shared) -----
router.get('/unitnotessuccess', (req, res) => {
  res.render('unit_views/unitnotessuccess', { layout: 'unitviewlayout' });
});

router.get('/exercises/view/:id', unitviewController.viewExercise);

router.get(
  '/exercises/:exerciseId/download/:fileRole',
  isAuthenticated,
  unitviewController.downloadExerciseFile
);

router.get('/templates/view/:id', unitviewController.viewTemplate);

module.exports = router;






