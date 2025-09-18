const express = require('express');
const router = express.Router();
const submitPromptNotesController = require('../../controllers/submitpromptnotesController');
const PromptSetProgress = require('../../models/prompt_models/promptsetprogress');

// ✅ Route to submit prompt notes (Works for Leaders, Group Members, and Members)
router.post('/submit-prompt-notes', (req, res, next) => {
    console.log("📌 Received POST Request for Prompt Notes");
    console.log("📌 Request Body:", req.body);
    console.log("📌 Session Data:", req.session);
    console.log("📌 Session User:", req.session.user);
    console.log("📌 req.user:", req.user);

    if (!req.body.notes || !req.body.promptSetId) {
        console.error("🚨 Missing Required Fields: Notes or Prompt Set ID");
    }

    next(); // Pass control to the controller
}, submitPromptNotesController.submitPromptNotes);

// ✅ Route to show success page, dynamically redirecting based on membershipType
router.get('/notessuccess', async (req, res) => {
    try {
        console.log("Checking session before rendering notessuccess:", req.session);

        const memberId = req.user?.id;
        if (!memberId) {
            console.error("Unauthorized access attempt.");
            return res.redirect(req.session.dashboard || '/dashboard/groupmember');
        }

        // ✅ Determine correct dashboard path for all user types
        const membershipType = req.user?.membershipType;
        let dashboardPath = '/dashboard';
        if (membershipType === 'leader') {
            dashboardPath = '/dashboard/leader';
        } else if (membershipType === 'group_member') {
            dashboardPath = '/dashboard/groupmember';
        } else {
            dashboardPath = '/dashboard/member'; // ✅ Ensure members redirect properly
        }

        // **Use session data if available, otherwise query from the database**
        let { remainingPrompts, targetDate, timeRemaining } = req.session;

        if (!remainingPrompts || !targetDate || !timeRemaining) {
            console.warn("⚠️ Session data incomplete. Attempting to fetch from database.");
            const progress = await PromptSetProgress.findOne({ memberId }).sort({ updatedAt: -1 });

            if (progress) {
                remainingPrompts = 20 - progress.completedPrompts.length;
                targetDate = new Date();
                targetDate.setDate(targetDate.getDate() + (remainingPrompts * 7)); // Assuming 1 prompt per week
                timeRemaining = `${remainingPrompts} weeks`;
            } else {
                console.warn("⚠️ No progress record found. Redirecting to dashboard.");
                return res.redirect(dashboardPath);
            }
        }

        // ✅ Ensure targetDate is a valid Date before calling .toDateString()
        const formattedTargetDate = targetDate instanceof Date ? targetDate.toDateString() : new Date(targetDate).toDateString();
        console.log(`✅ Rendering notessuccess page for ${membershipType}.`);
        console.log("📌 Received POST Request Data:", req.body);
        
        res.render('prompt_views/notessuccess', {
            layout: 'dashboardlayout',
            remainingPrompts,
            targetDate: formattedTargetDate,
            timeRemaining,
            dashboard: dashboardPath // ✅ Redirects based on correct membershipType
        });

    } catch (error) {
        console.error("❌ Error fetching prompt progress for success page:", error);
        return res.redirect(req.session.dashboard || '/dashboard/member'); // ✅ Default to member dashboard
    }
});

module.exports = router;








