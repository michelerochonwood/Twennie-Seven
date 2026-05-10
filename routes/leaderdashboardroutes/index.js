const express = require('express');

const router = express.Router();

const leaderDashboardController = require('../../controllers/leaderdashboardController');


// --- Auth gate ---
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// ------------------------------------------------------------
// ✅ GET /dashboard/leader/organization/success
// ------------------------------------------------------------
router.get('/organization/success', ensureAuthenticated, async (req, res, next) => {
  try {
    return leaderDashboardController.organizationSuccess(req, res);
  } catch (err) {
    console.error('Error in organization success route:', err);
    next(err);
  }
});

// --- GET /dashboard/leader ---
router.get('/', ensureAuthenticated, async (req, res, next) => {
  try {
    const dashboardData = await leaderDashboardController.renderLeaderDashboard(req, res);

    // Preserve your existing prompt-session logic
    if (dashboardData?.leaderPrompt1) {
      req.session.leaderPrompt1 = {
        promptSetId: dashboardData.leaderPrompt1.promptSetId?.toString(),
        promptIndex: Number(dashboardData.leaderPrompt1.promptIndex)
      };
      console.log('Session after setting leader prompt data:', req.session);
    } else {
      console.warn('No leader prompt data available to store in session.');
    }
  } catch (err) {
    console.error('Error in leader dashboard route:', err.message);
    next(err);
  }
});

// --- POST /dashboard/leader/account/details ---
router.post('/account/details', ensureAuthenticated, async (req, res, next) => {
  try {
    await leaderDashboardController.updateAccountDetails(req, res);
  } catch (err) {
    console.error('Error updating account details:', err);
    next(err);
  }
});

// --- POST /dashboard/leader/account/email-preferences ---
router.post('/account/email-preferences', ensureAuthenticated, async (req, res, next) => {
  try {
    await leaderDashboardController.updateEmailPreferences(req, res);
  } catch (err) {
    console.error('Error updating email preferences:', err);
    next(err);
  }
});

// --- POST /dashboard/leader/mark-seen ---
// Persist "last seen" count for a tab so green dots only show on increases
// --- POST /dashboard/leader/mark-seen ---
// Persist "last seen" count for a tab so green dots only show on increases
router.post('/mark-seen', ensureAuthenticated, async (req, res, next) => {
  try {
    await leaderDashboardController.markLeaderTabSeen(req, res);
  } catch (err) {
    console.error('Error marking leader tab seen:', err);
    next(err);
  }
});

router.get('/organization/search', ensureAuthenticated, async (req, res, next) => {
  try {
    return await leaderDashboardController.searchOrganizations(req, res);
  } catch (err) {
    console.error('Error searching organizations:', err);
    next(err);
  }
});
// ------------------------------------------------------------
// ✅ POST /dashboard/leader/organization/join
// Join an existing organization (domain verified)
// ------------------------------------------------------------
router.post('/organization/join', ensureAuthenticated, async (req, res, next) => {
  try {
    return await leaderDashboardController.joinOrganizationByDomain(req, res);
  } catch (err) {
    console.error('Error joining organization:', err);
    next(err);
  }
});

// ------------------------------------------------------------
// ✅ POST /dashboard/leader/organization/request-join
// Request to join an organization (approval flow)
// ------------------------------------------------------------
router.post('/organization/request-join', ensureAuthenticated, async (req, res, next) => {
  try {
    return await leaderDashboardController.requestJoinOrganization(req, res);
  } catch (err) {
    console.error('Error requesting org join:', err);
    next(err);
  }
});

// ------------------------------------------------------------
// ✅ POST /dashboard/leader/assigned-nuggets/unassign
// Unassign ONE member from ONE nugget tag
// body: { tagId, memberId }
// ------------------------------------------------------------
router.post('/assigned-nuggets/unassign', ensureAuthenticated, async (req, res, next) => {
  try {
    return await leaderDashboardController.unassignAssignedNugget(req, res);
  } catch (err) {
    console.error('Error unassigning assigned nugget:', err);
    next(err);
  }
});

// ------------------------------------------------------------
// ✅ Route wiring (wherever your leader dashboard routes live)
// Add this line:
// ------------------------------------------------------------

// Example:
router.post('/suggestions/:id/thanks', ensureAuthenticated, async (req, res, next) => {
  try {
    return await leaderDashboardController.acknowledgeSuggestedUnit(req, res);
  } catch (err) {
    console.error('Error acknowledging suggestion:', err);
    next(err);
  }
});



module.exports = router;
