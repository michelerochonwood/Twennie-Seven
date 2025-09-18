const PromptSet = require('../models/unit_models/promptset');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const { markPromptSetAsCompleted } = require('../controllers/promptsetcompletionController');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Member = require('../models/member_models/member');

module.exports = {
  submitPromptNotes: async (req, res) => {
    try {
      const { notes, promptSetId } = req.body;
      const memberId = req.user?._id || req.user?.id;
console.log("🔐 req.user:", req.user);
console.log("🧠 Member ID:", req.user?._id || req.user?.id);
      if (!memberId || !promptSetId) {
        return res.status(400).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Error',
          errorMessage: 'Missing user or prompt set information.'
        });
      }

      const user = await Leader.findById(memberId)
        || await GroupMember.findById(memberId)
        || await Member.findById(memberId);

      if (!user) {
        return res.status(404).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Error',
          errorMessage: 'User not found.'
        });
      }

      const membershipType = user.membershipType || "member";
      const promptSet = await PromptSet.findById(promptSetId);
      if (!promptSet) {
        return res.status(404).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Prompt Set Not Found',
          errorMessage: `Prompt set with ID ${promptSetId} could not be found.`
        });
      }

      const registration = await PromptSetRegistration.findOne({ memberId, promptSetId });
      const progress = await PromptSetProgress.findOneAndUpdate(
        { memberId, promptSetId },
        {
          $setOnInsert: {
            currentPromptIndex: 1,
            completedPrompts: [],
            notes: [],
            memberType: membershipType
          }
        },
        { new: true, upsert: true }
      );

      // Ensure arrays are initialized
      progress.completedPrompts ??= [];
      progress.notes ??= [];

      // Track current prompt
      const currentPrompt = progress.currentPromptIndex;
      if (!progress.completedPrompts.includes(currentPrompt)) {
        progress.completedPrompts.push(currentPrompt);
      }
      progress.notes.push(notes);
      progress.currentPromptIndex += 1;
      await progress.save();

      const remainingPrompts = 20 - progress.completedPrompts.length;
      const targetDate = registration?.targetCompletionDate?.toDateString?.() || 'not set';

      let timeRemaining = 'TBD';
      if (registration?.targetCompletionDate) {
        const now = new Date();
        const deadline = new Date(registration.targetCompletionDate);
        const daysLeft = Math.max(0, Math.ceil((deadline - now) / (1000 * 60 * 60 * 24)));
        const weeksLeft = Math.ceil(daysLeft / 7);
        timeRemaining = weeksLeft > 0 ? `${weeksLeft} week${weeksLeft === 1 ? '' : 's'}` : 'less than a week';
      }

      // ✅ Final prompt condition: All 20 prompts submitted
      if (progress.completedPrompts.length >= 20) {
        console.log(`🎉 Prompt set ${promptSetId} fully completed by ${memberId}. Redirecting to completion view.`);
        await markPromptSetAsCompleted(memberId, promptSetId, progress.notes);
        return res.redirect(`/promptsetcomplete/success?promptSetId=${promptSetId}`);
      }

      // ✅ Show regular success page for prompts 1–19
      return res.render('prompt_views/notessuccess', {
        layout: 'unitviewlayout',
        title: 'Notes Posted',
        remainingPrompts,
        targetDate,
        timeRemaining,
        badgeName: promptSet.badge?.name || 'a Twennie Badge',
        badgeImage: promptSet.badge?.image || '/images/default-badge.png',
        dashboard: membershipType === 'leader'
          ? '/dashboard/leader'
          : membershipType === 'group_member'
          ? '/dashboard/groupmember'
          : '/dashboard/member'
      });

    } catch (error) {
      console.error("❌ Error saving prompt notes:", error);
      res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'Something went wrong while saving your notes. Please try again.'
      });
    }
  }
};



























