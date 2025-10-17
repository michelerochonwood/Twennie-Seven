// routes/unitviewroutes/index.js
const express = require('express');
const router = express.Router();
const unitviewController = require('../../controllers/unitviewController');
const { ensureLoggedIn } = require('../../middleware/access');

// ----- unit views (require login) -----
router.get('/articles/view/:id',    ensureLoggedIn, unitviewController.viewArticle);
router.get('/videos/view/:id',      ensureLoggedIn, unitviewController.viewVideo);
router.get('/interviews/view/:id',  ensureLoggedIn, unitviewController.viewInterview);
router.get('/promptsets/view/:id',  ensureLoggedIn, unitviewController.viewPromptset);
router.get('/exercises/view/:id',   ensureLoggedIn, unitviewController.viewExercise);
router.get('/templates/view/:id',   ensureLoggedIn, unitviewController.viewTemplate);

// Upcoming: logged-in users may view
router.get('/upcoming/view/:id',    ensureLoggedIn, unitviewController.viewUpcoming);

// ----- The Mine (keep as you had; if you want paid-only at router, add a stricter guard) -----
router.get('/', (req, res) => res.redirect('/unitviews/mine'));
router.get('/mine', (req, res) => {
  return res.render('unit_views/mine_list', {
    layout: 'unitviewlayout',
    listTitle: 'Welcome to the Twennie Mine',
    listSubtitle: 'Choose a path to explore Nuggets by Client, Region, or Discipline.',
    items: [
      { label: 'client',     href: '/unitviews/mine/clients' },
      { label: 'region',     href: '/unitviews/mine/regions' },
      { label: 'discipline', href: '/unitviews/mine/disciplines' },
    ],
    itemType: 'category'
  });
});
router.get('/mine/clients',     ensureLoggedIn, (req, res, next) => unitviewController.viewMineClients(req, res, next));
router.get('/mine/regions',     ensureLoggedIn, (req, res, next) => unitviewController.viewMineRegions(req, res, next));
router.get('/mine/disciplines', ensureLoggedIn, (req, res, next) => unitviewController.viewMineDisciplines(req, res, next));

// Nuggets (leave as login-only, or tighten later)
router.get('/nuggets/view/:id', ensureLoggedIn, unitviewController.viewNugget);

// Shared success view
router.get('/unitnotessuccess', (req, res) => {
  res.render('unit_views/unitnotessuccess', { layout: 'unitviewlayout' });
});

module.exports = router;






