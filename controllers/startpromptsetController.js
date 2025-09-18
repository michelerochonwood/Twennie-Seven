const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const PromptSet = require('../models/unit_models/promptset');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Member = require('../models/member_models/member');

module.exports = {
  startPromptSet: async (req, res) => {
    try {
      const { promptSetId } = req.body;
      const memberId = req.user?.id;

      if (!memberId || !promptSetId) {
        return res.status(400).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Error',
          errorMessage: 'Missing user or prompt set information.',
        });
      }

      // Fetch or initialize progress
      let progress = await PromptSetProgress.findOne({ memberId, promptSetId });

      if (!progress) {
        progress = new PromptSetProgress({
          memberId,
          promptSetId,
          currentPromptIndex: 1,
          completedPrompts: [],
          notes: []
        });
        await progress.save();
        console.log(`✅ New progress initialized for user ${memberId}, starting at Prompt 1`);
      } else if (progress.currentPromptIndex === 0) {
        progress.currentPromptIndex = 1;
        await progress.save();
        console.log(`🔁 Progress updated to skip Prompt 0 for user ${memberId}`);
      } else {
        console.log(`ℹ️ User ${memberId} already started this set at Prompt ${progress.currentPromptIndex}`);
      }

      // Determine dashboard path
      const leader = await Leader.findById(memberId);
      const groupMember = await GroupMember.findById(memberId);
      const dashboardPath = leader
        ? '/dashboard/leader'
        : groupMember
        ? '/dashboard/groupmember'
        : '/dashboard/member';

      // Fetch prompt set details
      const promptSet = await PromptSet.findById(promptSetId);
      if (!promptSet) {
        return res.status(404).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Error',
          errorMessage: 'Prompt set not found.',
        });
      }

      // Fetch registration to get targetCompletionDate
      const registration = await PromptSetRegistration.findOne({ memberId, promptSetId });
      const targetDate = registration?.targetCompletionDate
        ? new Date(registration.targetCompletionDate)
        : null;

      const today = new Date();
      const remainingDays = targetDate
        ? Math.max(0, Math.ceil((targetDate - today) / (1000 * 60 * 60 * 24)))
        : 'Unknown';

      const remainingPrompts = 21 - (progress.completedPrompts?.length || 0);

      // Fetch completion record to get badge info
      const completionRecord = await PromptSetCompletion.findOne({ memberId, promptSetId });
const badgeName = completionRecord?.earnedBadge?.name || promptSet.badge?.name || 'Default Badge';
const badgeImage = completionRecord?.earnedBadge?.image || promptSet.badge?.image || '/images/default-badge.png';

      // Render the getstarted view
return res.render('prompt_views/getstarted', {
  layout: 'dashboardlayout',
  title: 'Get Started | Twennie',

  // ✅ Displayed values in the view
  promptSetTitle: promptSet.promptset_title,
  frequency: registration?.frequency || 'unspecified',
  targetCompletionDate: targetDate ? targetDate.toDateString() : 'Not Set',

  // ✅ Progress details
  remainingPrompts,
  timeRemaining: typeof remainingDays === 'number' ? `${remainingDays} days` : 'Unknown',

  // ✅ Badge (from completion if it exists, fallback to promptSet.badge)
  badgeName: completionRecord?.earnedBadge?.name || promptSet.badge?.name || 'Default Badge',
  badgeImage: completionRecord?.earnedBadge?.image || promptSet.badge?.image || '/images/default-badge.png',

  // ✅ Navigation
  dashboard: dashboardPath
});


    } catch (error) {
      console.error("❌ Error starting prompt set:", error);
      res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while starting your prompt set. Please try again.',
      });
    }
  }
};


