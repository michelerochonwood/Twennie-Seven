// routes/reportingroutes/index.js
// routes/reportingroutes/index.js
const express = require("express");
const router = express.Router();

const ensureAuthenticated = require("../../middleware/ensureAuthenticated");
const reportingController = require("../../controllers/reportingController");

// ---------- Leader report views ----------
router.get("/memberengagement", ensureAuthenticated, reportingController.getMemberEngagementReport);
router.get("/promptsetscompleted", ensureAuthenticated, reportingController.getPromptSetsCompletedReport);
router.get("/unitscompleted", ensureAuthenticated, reportingController.getUnitsCompletedReport);
router.get("/nuggetsmonitored", ensureAuthenticated, reportingController.getNuggetsMonitoredReport);

// ---------- Group member report views ----------
router.get("/mycompletedpromptsets", ensureAuthenticated, reportingController.getMyCompletedPromptSetsReport);
router.get("/mylearningnotes", ensureAuthenticated, reportingController.getMyLearningNotesReport);

// ---------- Individual member report views ----------
router.get("/mycompletedpromptsets-individual", ensureAuthenticated, reportingController.getMyCompletedPromptSetsReportIndividual);
router.get("/mylearningnotes-individual", ensureAuthenticated, reportingController.getMyLearningNotesReportIndividual);

module.exports = router;

