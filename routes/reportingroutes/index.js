// routes/reportingroutes/index.js
const express = require("express");
const router = express.Router();

const ensureAuthenticated = require("../../middleware/ensureAuthenticated");
const reportingController = require("../../controllers/reportingController");

// ---------- HTML report views ----------
router.get("/memberengagement", ensureAuthenticated, reportingController.getMemberEngagementReport);
router.get("/promptsetscompleted", ensureAuthenticated, reportingController.getPromptSetsCompletedReport);
router.get("/mycompletedpromptsets", ensureAuthenticated, reportingController.getMyCompletedPromptSetsReport);
router.get("/mylearningnotes", ensureAuthenticated, reportingController.getMyLearningNotesReport);
router.get("/unitscompleted", ensureAuthenticated, reportingController.getUnitsCompletedReport);

// ---------- Nuggets being monitored ----------
router.get("/nuggetsmonitored", ensureAuthenticated, reportingController.getNuggetsMonitoredReport);

module.exports = router;

