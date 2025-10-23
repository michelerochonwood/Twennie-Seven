const express = require("express");
const router = express.Router();
const ensureAuthenticated = require("../../middleware/ensureAuthenticated");
const reportingController = require("../../controllers/reportingController");

// Routes for report views
router.get("/memberengagement", ensureAuthenticated, reportingController.getMemberEngagementReport);
router.get("/promptsetscompleted", ensureAuthenticated, reportingController.getPromptSetsCompletedReport);
router.get("/teamengagement", ensureAuthenticated, reportingController.getTeamEngagementReport);
router.get("/unitscompleted", ensureAuthenticated, reportingController.getUnitsCompletedReport);
router.get('/mypromptsets', ensureAuthenticated, reportingController.getIndividualPromptSetCompletionReport);
router.get('/groupmypromptsets', ensureAuthenticated, reportingController.getGroupMemberPromptSetCompletionReport);

router.get('/memberengagement.csv', isAuthenticated, reportsController.memberEngagementCSV);
router.get('/teamengagement.csv', isAuthenticated, reportsController.teamEngagementCSV);
router.get('/promptsetscompleted.csv', isAuthenticated, reportsController.promptSetsCompletedCSV);
router.get('/unitscompleted.csv', isAuthenticated, reportsController.unitsCompletedCSV);


module.exports = router;
