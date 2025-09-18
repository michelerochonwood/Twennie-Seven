const PromptSet = require('../models/unit_models/promptset');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Member = require('../models/member_models/member');

module.exports = {
  markPromptSetAsCompleted: async (memberId, promptSetId, notes) => {
    try {
      console.log(`🏁 Marking prompt set ${promptSetId} as completed for member ${memberId}`);

      const user = await Leader.findById(memberId) || 
                   await GroupMember.findById(memberId) || 
                   await Member.findById(memberId);

      if (!user) {
        console.error(`❌ No user found for ID: ${memberId}`);
        return;
      }

      const membershipType = user.membershipType || "member";

      const existingCompletion = await PromptSetCompletion.findOne({ memberId, promptSetId });
      if (existingCompletion) {
        console.warn(`⚠️ Already completed: promptSetId ${promptSetId}, memberId ${memberId}`);
        return;
      }

      const promptSet = await PromptSet.findById(promptSetId);
      if (!promptSet) {
        console.error(`❌ Prompt Set not found: ${promptSetId}`);
        return;
      }

      const completion = new PromptSetCompletion({
        memberId,
        memberType: membershipType,
        promptSetId,
        earnedBadge: {
          image: promptSet.badge?.image || '/images/default-badge.png',
          name: promptSet.badge?.name || 'a Twennie Badge'
        },
        notes
      });

      await completion.save();
      console.log(`✅ Prompt set marked complete: ${promptSet.promptset_title} for ${membershipType}`);
    } catch (error) {
      console.error("❌ Error saving prompt set completion:", error);
    }
  },

  getCompletedPromptSets: async (req, res) => {
    try {
      const memberId = req.user?.id;
      if (!memberId) {
        return res.status(401).json({ success: false, errorMessage: "Unauthorized. Please log in." });
      }

      console.log(`📚 Fetching completed sets for: ${memberId}`);

      const completions = await PromptSetCompletion.find({ memberId }).populate('promptSetId');

      const formatted = completions.map(entry => ({
        promptSetTitle: entry.promptSetId?.promptset_title || 'Unknown Title',
        mainTopic: entry.promptSetId?.main_topic || 'No Topic',
        completedAt: entry.completedAt ? new Date(entry.completedAt).toDateString() : 'Date Unknown',
        badge: {
          name: entry.earnedBadge?.name || 'a Twennie Badge',
          image: entry.earnedBadge?.image || '/images/default-badge.png'
        }
      }));

      return res.json({ success: true, completedPromptSets: formatted });
    } catch (error) {
      console.error("❌ Failed to fetch completed prompt sets:", error);
      return res.status(500).json({ success: false, errorMessage: "Unable to fetch completed prompt sets." });
    }
  },

  promptsetCompleteSuccess: async (req, res) => {
    try {
      const { promptSetId } = req.query;

      if (!promptSetId) {
        return res.status(400).render('error', {
          title: 'Error',
          errorMessage: 'Missing promptSetId. Try again.'
        });
      }

      const promptSet = await PromptSet.findById(promptSetId);
      if (!promptSet) {
        return res.status(404).render('error', {
          title: 'Error',
          errorMessage: 'Prompt set not found.'
        });
      }

      const dashboardPath = req.user?.membershipType === 'leader'
        ? '/dashboard/leader'
        : req.user?.membershipType === 'group_member'
        ? '/dashboard/groupmember'
        : '/dashboard/member';

      return res.render('prompt_views/promptsetcompletesuccess', {
        layout: 'unitviewlayout',
        title: promptSet.promptset_title || 'Prompt Set Complete',
        purpose: promptSet.purpose || 'No purpose listed',
        badge: promptSet.badge?.image || '/images/default-badge.png',
        badgeName: promptSet.badge?.name || 'a Twennie Badge',
        dashboard: dashboardPath
      });
    } catch (error) {
      console.error("❌ Error loading completion success view:", error);
      return res.status(500).render('error', {
        title: 'Error',
        errorMessage: 'There was a problem displaying your completion page.'
      });
    }
  }
};








