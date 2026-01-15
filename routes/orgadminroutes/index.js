// routes/dashboard/leaderOrgAdminRoutes.js
const express = require('express');
const router = express.Router();

const ensureAuthenticated = require('../../middleware/ensureAuthenticated');
const requireOrgAdmin = require('../../middleware/requireOrgAdmin');

const orgadminController = require('../../controllers/orgadminController');

// NOTE: Mount this router like:
// app.use('/dashboard/leader/org-admin', require('./routes/dashboard/leaderOrgAdminRoutes'));

// ------------------------------------------------------------
// Admin-mode dashboard tabs (GET)
// Base: /dashboard/leader/org-admin
// ------------------------------------------------------------
router.get('/my-organization', ensureAuthenticated, requireOrgAdmin, orgadminController.myOrganization);
router.get('/groups-leaders',  ensureAuthenticated, requireOrgAdmin, orgadminController.groupsLeaders);
router.get('/requests',        ensureAuthenticated, requireOrgAdmin, orgadminController.requests);
router.get('/suggestions',     ensureAuthenticated, requireOrgAdmin, orgadminController.suggestions);
router.get('/company-library', ensureAuthenticated, requireOrgAdmin, orgadminController.companyLibrary);
router.get('/reports',         ensureAuthenticated, requireOrgAdmin, orgadminController.reports);

// ------------------------------------------------------------
// Join request review actions (POST)
// Base: /dashboard/leader/org-admin
// ------------------------------------------------------------
router.post(
  '/join-requests/:requestId/approve',
  ensureAuthenticated,
  requireOrgAdmin,
  orgadminController.approveJoinRequest
);

router.post(
  '/join-requests/:requestId/reject',
  ensureAuthenticated,
  requireOrgAdmin,
  orgadminController.rejectJoinRequest
);

module.exports = router;

