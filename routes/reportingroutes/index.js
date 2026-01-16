// routes/reportingroutes/index.js
const express = require("express");
const router = express.Router();

const ensureAuthenticated = require("../../middleware/ensureAuthenticated");
const reportingController = require("../../controllers/reportingController");

// ---------- HTML report views ----------
router.get("/memberengagement",     ensureAuthenticated, reportingController.getMemberEngagementReport);
router.get("/promptsetscompleted",  ensureAuthenticated, reportingController.getPromptSetsCompletedReport);
router.get("/teamengagement",       ensureAuthenticated, reportingController.getTeamEngagementReport);
router.get("/unitscompleted",       ensureAuthenticated, reportingController.getUnitsCompletedReport);

// ✅ Nuggets being monitored
router.get("/nuggetsmonitored",     ensureAuthenticated, reportingController.getNuggetsMonitoredReport);

// Individual / Group member prompt-set reports
router.get("/mypromptsets",         ensureAuthenticated, reportingController.getIndividualPromptSetCompletionReport);
router.get("/groupmypromptsets",    ensureAuthenticated, reportingController.getGroupMemberPromptSetCompletionReport);

module.exports = router;


