// routes/dashboard/leaderOrgAdminRoutes.js
const express = require('express');
const router = express.Router();

const ensureAuthenticated = require('../../middleware/ensureAuthenticated');
const requireOrgAdmin = require('../../middleware/requireOrgAdmin');

// Controller (we’ll create next)
const leaderOrgAdminController = require('../../controllers/orgadminController');

// Base: /dashboard/leader/org-admin

router.get('/my-organization', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.myOrganization(req, res);
  } catch (err) {
    next(err);
  }
});

router.get('/groups-leaders', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.groupsLeaders(req, res);
  } catch (err) {
    next(err);
  }
});

router.get('/requests', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.requests(req, res);
  } catch (err) {
    next(err);
  }
});

router.get('/suggestions', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.suggestions(req, res);
  } catch (err) {
    next(err);
  }
});

router.get('/company-library', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.companyLibrary(req, res);
  } catch (err) {
    next(err);
  }
});

router.get('/reports', ensureAuthenticated, requireOrgAdmin, (req, res, next) => {
  try {
    return leaderOrgAdminController.reports(req, res);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
