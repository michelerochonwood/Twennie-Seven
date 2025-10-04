// File: routes/unitviewroutes/index.js
const express = require('express');
const router = express.Router();
const unitviewController = require('../../controllers/unitviewController');

// Lightweight auth gate for JSON POSTs (views themselves remain open;
// controller enforces visibility rules)
const isAuthenticated = (req, res, next) => {
  if (req.user) return next();
  return res.status(401).json({ error: 'Not authenticated' });
};

// ----- existing unit routes -----
router.get('/articles/view/:id', unitviewController.viewArticle);
router.get('/videos/view/:id', unitviewController.viewVideo);
router.get('/interviews/view/:id', unitviewController.viewInterview);
router.get('/promptsets/view/:id', unitviewController.viewPromptset);
router.get('/exercises/view/:id', unitviewController.viewExercise);
router.get('/templates/view/:id', unitviewController.viewTemplate);

// ----- nuggets (new) -----
router.get('/nuggets/view/:id', unitviewController.viewNugget);
router.get('/mine/clients', unitviewController.viewMineClients);
router.get('/mine/regions', unitviewController.viewMineRegions);
router.get('/mine/disciplines', unitviewController.viewMineDisciplines);

// ----- upcoming unit -----
router.get('/upcoming/view/:id', unitviewController.viewUpcoming);

// ----- notes success (shared) -----
router.get('/unitnotessuccess', (req, res) => {
  res.render('unit_views/unitnotessuccess', { layout: 'unitviewlayout' });
});

module.exports = router;




