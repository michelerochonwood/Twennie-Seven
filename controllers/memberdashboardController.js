const Member = require('../models/member_models/member');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const Tag = require('../models/tag');
const path = require('path'); // ✅ Fix for "ReferenceError: path is not defined"
const fs = require('fs'); // ✅ Ensure file system functions work
const MemberProfile = require('../models/profile_models/member_profile');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const TopicSuggestion = require('../models/topic/topic_suggestion');
const Upcoming = require('../models/unit_models/upcoming');

 


async function resolveAuthorById(authorId) {
    let author = await Member.findById(authorId).select('username profileImage professionalTitle topics');
    return author ? { name: author.username, image: author.profileImage, professionalTitle: author.professionalTitle, topics: author.topics } : 
           { name: 'Unknown Author', image: null, professionalTitle: 'No title available', topics: [] };
}

async function fetchTaggedUnits(userId) {
  try {
    const tags = await Tag.find({ createdBy: userId }).lean();
    if (!tags.length) return [];

    // Build a list of unit fetch targets by type
    const unitMap = {
      article: [],
      video: [],
      promptset: [],
      interview: [],
      exercise: [],
      template: []
    };

    // Build a tag lookup for later association
    const tagLookup = new Map(); // key: `${itemId}-${unitType}`, value: tagId

    tags.forEach(tag => {
      tag.associatedUnits.forEach(({ item, unitType }) => {
        if (unitMap[unitType]) {
          unitMap[unitType].push(item.toString());
          tagLookup.set(`${item.toString()}-${unitType}`, tag._id.toString());
        }
      });
    });

    const [articles, videos, promptSets, interviews, exercises, templates] = await Promise.all([
      Article.find({ _id: { $in: unitMap.article } }).lean(),
      Video.find({ _id: { $in: unitMap.video } }).lean(),
      PromptSet.find({ _id: { $in: unitMap.promptset } }).lean(),
      Interview.find({ _id: { $in: unitMap.interview } }).lean(),
      Exercise.find({ _id: { $in: unitMap.exercise } }).lean(),
      Template.find({ _id: { $in: unitMap.template } }).lean()
    ]);

    const tagResult = (units, type, titleField) =>
      units.map(unit => ({
        unitType: type,
        title: unit[titleField] || `Untitled ${type}`,
        mainTopic: unit.main_topic || "No topic",
        _id: unit._id,
        tagId: tagLookup.get(`${unit._id.toString()}-${type}`)
      }));

    return [
      ...tagResult(articles, 'article', 'article_title'),
      ...tagResult(videos, 'video', 'video_title'),
      ...tagResult(promptSets, 'promptset', 'promptset_title'),
      ...tagResult(interviews, 'interview', 'interview_title'),
      ...tagResult(exercises, 'exercise', 'exercise_title'),
      ...tagResult(templates, 'template', 'template_title')
    ];

  } catch (error) {
    console.error("❌ Error fetching tagged units:", error);
    return [];
  }
}



const topicMappings = {
    'AI in Consulting': 'aiinconsulting',
    'AI in Project Management': 'aiinprojectmanagement',
    'AI in Adult Learning': 'aiinadultlearning',
    'Project Management': 'projectmanagement',
    'Workplace Culture': 'workplaceculture',
    'The Pareto Principle': 'theparetoprinciple',
    'Career Development in Technical Services': 'careerdevelopmentintechnicalservices',
    'Soft Skills in Technical Environments': 'softskillsintechnicalenvironments',
    'Business Development in Technical Services': 'businessdevelopmentintechnicalservices',
    'Finding Projects Before they Become RFPs': 'findingprojectsbeforetheybecomerfps',
    'Un-Commoditizing Your Services by Delivering What Clients Truly Value': 'uncommoditizingbydelivering',
    'Proposal Management': 'proposalmanagement',
    'Proposal Strategy': 'proposalstrategy',
    'Designing a Proposal Process': 'proposalprocess',
    'Conducting Color Reviews of Proposals': 'colorreviews',
    'Storytelling in Technical Marketing': 'storytellingintechnicalmarketing',
    'Client Experience': 'clientexperience',
    'Social Media, Advertising, and Other Mysteries': 'socialmediaadvertisingandothermysteries',
    'Pull Marketing': 'pullmarketing',
    'Emotional Intelligence': 'emotionalintelligence',
    'People Before Profit': 'peoplebeforeprofit',
    'Non-Technical Roles in Technical Environments': 'nontechnicalrolesintechnicalenvironments',
    'Leadership in Technical Services': 'leadershipintechnicalservices',
    'Leading Change': 'leadingchange',
    'The Advantage of Failure': 'theadvantageoffailure',
    'Social Entrepreneurship': 'socialentrepreneurship',
    'Employee Experience': 'employeeexperience',
    'Project Management Software': 'projectmanagementsoftware',
    'CRM Platforms': 'crmplatforms',
    'Client Feedback Software': 'clientfeedbacksoftware',
    'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
    'Remote or Hybrid Work': 'remoteorhybridwork',
    'Four Day Work Week': 'fourdayworkweek',
    'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
    'Team Building in Technical Consulting': 'teambuildingintechnicalconsulting',
};

// Mapping topic slugs to their corresponding view filenames
const topicViewMappings = {
    'aiinconsulting': 'single_topic_aiconsulting',
    'aiinadultlearning': 'single_topic_ailearn',
    'aiinprojectmanagement': 'single_topic_aiprojectmgmt',
    'businessdevelopmentintechnicalservices': 'single_topic_bd',
    'findingprojectsbeforetheybecomerfps': 'single_topic_findingprojects',
    'uncommoditizingbydelivering': 'uncommoditizingbydelivering',
    'careerdevelopmentintechnicalservices': 'single_topic_careerdev',
    'clientexperience': 'single_topic_clientex',
    'clientfeedbacksoftware': 'single_topic_clientfeedback',
    'conductingcolorreviews': 'single_topic_colorreviews',
    'crmplatforms': 'single_topic_crm',
    'emotionalintelligence': 'single_topic_emotionali',
    'employeeexperience': 'single_topic_employeeex',
    'theadvantageoffailure': 'single_topic_failure',
    'fourdayworkweek': 'single_topic_fourday',
    'leadershipintechnicalservices': 'single_topic_leadership',
    'leadingchange': 'single_topic_change',
    'leadinggroupsontwennie': 'single_topic_leadinggroupsontwennie',
    'mentalhealthinconsultingenvironments': 'single_topic_mental',
    'nontechnicalrolesintechnicalenvironments': 'single_topic_nontechnical',
    'theparetoprinciple': 'single_topic_pareto',
    'peoplebeforeprofit': 'single_topic_peoplebefore',
    'thepowerofplayintheworkplace': 'single_topic_play',
    'projectmanagementsoftware': 'single_topic_pmsoftware',
    'projectmanagement': 'single_topic_projectmgmt',
    'proposalmanagement': 'single_topic_proposalmgmt',
    'proposalstrategy': 'single_topic_proposalstrat',
    'proposalprocess': 'single_topic_proposalprocess',
    'pullmarketing': 'single_topic_pullmarketing',
    'remoteorhybridwork': 'single_topic_remote',
    'socialentrepreneurship': 'single_topic_social',
    'socialmediaadvertisingandothermysteries': 'single_topic_socialmedia',
    'softskillsintechnicalenvironments': 'single_topic_softskills',
    'storytellingintechnicalmarketing': 'single_topic_storytelling',
    'teambuildingintechnicalconsulting': 'single_topic_teambuilding',
    'workplaceculture': 'single_topic_workplaceculture'
};

// Function to get subtopics from topics.json
function getSubtopics(topicTitle) {
    const topicsFilePath = path.join(__dirname, '../public/data/topics.json'); // ✅ Now path is defined

    if (!fs.existsSync(topicsFilePath)) {
        console.error('topics.json file is missing.');
        return [];
    }

    const topicsData = JSON.parse(fs.readFileSync(topicsFilePath, 'utf8'));
    const topic = topicsData.topics.find(t => t.title === topicTitle);

    return topic ? topic.subtopics : []; // ✅ Return an empty array if no subtopics found
}



async function getPromptSchedule(memberId, promptSetId) {
    let targetDate = null;

    const registration = await PromptSetRegistration.findOne({ memberId, promptSetId });

    if (registration) {
        targetDate = registration.targetCompletionDate;
    }

    if (!targetDate) {
        console.warn(`No target date found for member ${memberId} and promptSetId ${promptSetId}`);
        return null;
    }

    // ✅ Calculate remaining prompts and recommended due dates
    const today = new Date();
    targetDate = new Date(targetDate);
    const remainingDays = Math.max(0, Math.ceil((targetDate - today) / (1000 * 60 * 60 * 24)));
    // ✅ First fetch completed prompt sets
const completedRecords = await PromptSetCompletion.find({ memberId }).populate('promptSetId');



    const progress = await PromptSetProgress.findOne({ memberId, promptSetId });
    const remainingPrompts = progress ? 20 - progress.completedPrompts.length : 20;

    const spread = remainingPrompts > 0 ? Math.floor(remainingDays / remainingPrompts) : 0;

    return {
        targetCompletionDate: targetDate.toDateString(),
        recommendedCompletionDate: new Date(today.getTime() + spread * 24 * 60 * 60 * 1000).toDateString(),
        remainingDays,
        remainingPrompts,
        spread
    };
}




module.exports = {
  renderMemberDashboard: async (req, res) => {
    try {
      // Resolve current member id (works with legacy session or Passport)
      const id = req.session?.user?.id || req.user?._id?.toString();
      if (!id) return res.redirect('/auth/login');

      const userData = await Member.findById(id)
        .select('username email emailPreferenceLevel profileImage professionalTitle organization topics accessLevel mfa.enabled mfa.method mfa.recoveryCodes mfa.updatedAt')
        .lean();

      if (!userData) {
        throw new Error(`Member with ID ${id} not found.`);
      }

      const memberProfile = await MemberProfile.findOne({ memberId: id }).select('profileImage');

      const topicSuggestions = await TopicSuggestion.find({
        suggestedBy: id,
        memberType: 'Member'
      }).sort({ submittedAt: -1 }).lean();

      // --- Build MFA status for dashboard (member) ---
      const mfa = userData?.mfa || {};
      const mfaStatus = {
        enabled: !!mfa.enabled,
        recoveryCodesRemaining: Array.isArray(mfa.recoveryCodes) ? mfa.recoveryCodes.length : 0,
        updatedAtFormatted: mfa.updatedAt
          ? new Date(mfa.updatedAt).toLocaleString('en-CA', {
              year: 'numeric', month: 'short', day: '2-digit',
              hour: '2-digit', minute: '2-digit'
            })
          : null
      };

            const accessLevelLabels = {
                free_individual: 'Free',
                contributor_individual: 'Contributing',
                paid_individual: 'Paid'
              };
              
              const accessLevelLabel = accessLevelLabels[userData.accessLevel] || 'Member';

            if (!userData) {
                throw new Error(`Member with ID ${id} not found.`);
            }

            console.log('Member data fetched:', userData);


            let registeredPromptSets = [];
            let promptSchedules = [];

            const memberRegistrations = await PromptSetRegistration.find({ memberId: id }).populate('promptSetId');


            // ✅ Process each registered prompt set
            await Promise.all(
                memberRegistrations.map(async (registration) => {
                    const promptSet = await PromptSet.findById(registration.promptSetId);
                    if (!promptSet) 
                        return;

                    // ✅ Fetch progress
                    const progress = await PromptSetProgress.findOne({ memberId: id, promptSetId: registration.promptSetId });

                    const currentPromptIndex = progress?.currentPromptIndex ?? 0; // ✅ Ensure first prompt is always 0

                    console.log(`Progress for promptSetId ${registration.promptSetId._id}: ${currentPromptIndex}`);

                    const headlineKey = `prompt_headline${currentPromptIndex}`;
                    const promptKey = `Prompt${currentPromptIndex}`;
                    
                    
                    const promptHeadline = promptSet[headlineKey] || "No headline found";
                    const promptText = promptSet[promptKey] || "No prompt text found";

                    const isCompleted = progress?.completedPrompts?.length >= 20;

                    if (!isCompleted) { 
                        registeredPromptSets.push({
                            registrationId: registration._id,
                            promptSetId: registration.promptSetId._id.toString(),
                            promptSetTitle: promptSet.promptset_title,
                            frequency: registration.frequency,
                            mainTopic: promptSet.main_topic,
                            purpose: promptSet.purpose,
                            promptHeadline,  // ✅ Ensure this is always Prompt0
                            promptText,      // ✅ Ensure this is always Prompt0
                            promptIndex: currentPromptIndex ?? 0,  // ✅ Use the dynamic prompt index
                        });
                        
                    }

console.log("🔍 Checking prompt retrieval...");
console.log(`   Available Keys in promptSet:`, Object.keys(promptSet)); 
console.log(`   headlineKey: prompt_headline0`);
console.log(`   promptKey: Prompt0`);
console.log(`   Retrieved Headline:`, promptSet["prompt_headline0"]);
console.log(`   Retrieved Text:`, promptSet["Prompt0"]);
                    

                    // ✅ Get prompt schedule
                    promptSchedules.push(await getPromptSchedule(id, registration.promptSetId));
                })
            );

            // ✅ Fetch completed prompt sets
// ✅ Fetch completed prompt sets
// ✅ First fetch completed prompt sets
const completedRecords = await PromptSetCompletion.find({ memberId: id }).populate('promptSetId');
const completedIds = new Set(completedRecords.map(record => record.promptSetId._id.toString()));

// ✅ Then fetch in-progress prompt records
const progressRecords = await PromptSetProgress.find({ memberId: id }).populate('promptSetId');

let currentPromptSets = [];

if (progressRecords.length > 0) {
    progressRecords.forEach(record => {
        const promptSetId = record.promptSetId._id.toString();
        if (!completedIds.has(promptSetId)) {
            const progressPercentage = (record.completedPrompts?.length / 20) * 100 || 0;
            currentPromptSets.push({
                promptSetTitle: record.promptSetId.promptset_title,
                frequency: record.promptSetId.suggested_frequency,
                progress: `${progressPercentage}%`,
                targetCompletionDate: record.promptSetId.target_completion_date || "Not Set",
                promptIndex: record.currentPromptIndex || 0
            });
        }
    });
}

// ✅ Format completed sets for view
const formattedCompletedSets = completedRecords.map(record => ({
    promptSetTitle: record.promptSetId.promptset_title,
    frequency: record.promptSetId.suggested_frequency,
    mainTopic: record.promptSetId.main_topic,
    completedAt: record.completedAt ? new Date(record.completedAt).toDateString() : "Unknown Date",
    badge: record.earnedBadge
}));



            console.log("Final session before rendering:", req.session);

            // ✅ Fetch tagged and contributed units
// ✅ Fetch tagged and contributed units
const memberTaggedUnits = await fetchTaggedUnits(id);

const [
  memberArticles,
  memberVideos,
  memberPromptSets,
  memberInterviews,
  memberExercises,
  memberTemplates
] = await Promise.all([
  Article.find({ 'author.id': id }),
  Video.find({ 'author.id': id }),
  PromptSet.find({ 'author.id': id }),
  Interview.find({ 'author.id': id }),
  Exercise.find({ 'author.id': id }),
  Template.find({ 'author.id': id })
]);

// 👇 my upcoming units (ownership via createdBy on Upcoming)
const memberUpcomings = await Upcoming.find({ createdBy: id });

let memberUnits = await Promise.all(
  [...memberArticles, ...memberVideos, ...memberPromptSets, ...memberInterviews, ...memberExercises, ...memberTemplates].map(async (unit) => {
    const author = await resolveAuthorById(unit.author?.id || unit.author);
    return {
      unitType: unit.unitType || unit.constructor?.modelName || 'Unknown',
      title:
        unit.article_title ||
        unit.video_title ||
        unit.promptset_title ||
        unit.interview_title ||
        unit.exercise_title ||
        unit.template_title ||
        'Untitled Unit',
      status: unit.status || 'Unknown',
      mainTopic: unit.main_topic || 'No topic',
      _id: unit._id,
      author: author.name
    };
  })
);

// 👇 append upcoming rows (for the member’s own upcoming contributions)
const myUpcomingRows = (memberUpcomings || []).map((u) => ({
  unitType: 'upcoming',
  plannedType: u.unit_type,                 // e.g., 'video'
  title: u.title,
  status: u.status || 'in production',
  mainTopic: u.main_topic || 'No topic',
  _id: u._id,
  projectedRelease: u.projected_release_at
}));

memberUnits = [...memberUnits, ...myUpcomingRows];


            // Attach subtopics and slugs for the member's topics
// Attach subtopics and slugs for the member's topics (Fix for missing topics)
const selectedTopics = {
    topic1: userData.topics?.topic1
        ? {
            title: userData.topics.topic1,
            subtopics: getSubtopics(userData.topics.topic1), // ✅ Fetch subtopics from topics.json
            slug: topicMappings[userData.topics.topic1] || "unknown-topic",
            viewName: topicViewMappings[topicMappings[userData.topics.topic1]] || "not_found"
        }
        : null,
    topic2: userData.topics?.topic2
        ? {
            title: userData.topics.topic2,
            subtopics: getSubtopics(userData.topics.topic2), // ✅ Fetch subtopics from topics.json
            slug: topicMappings[userData.topics.topic2] || "unknown-topic",
            viewName: topicViewMappings[topicMappings[userData.topics.topic2]] || "not_found"
        }
        : null,
    topic3: userData.topics?.topic3
        ? {
            title: userData.topics.topic3,
            subtopics: getSubtopics(userData.topics.topic3), // ✅ Fetch subtopics from topics.json
            slug: topicMappings[userData.topics.topic3] || "unknown-topic",
            viewName: topicViewMappings[topicMappings[userData.topics.topic3]] || "not_found"
        }
        : null
};


// ✅ Log topics to debug missing data
console.log("🔍 Selected Topics for Member Dashboard:", selectedTopics);
const emailPreferenceLevel = [1, 2, 3].includes(Number(userData?.emailPreferenceLevel))
  ? Number(userData.emailPreferenceLevel)
  : 1;

const memberAccount = {
  // If you have a separate "name" field, use it; otherwise username is a good display-name here.
  name: userData?.username || 'Member',
  email: userData?.email || req.session?.user?.email || '',
  username: userData?.username || ''
};


return res.render("member_dashboard", {
  layout: "dashboardlayout",
  title: "Member Dashboard",
  csrfToken: req.csrfToken(),
  member: {
    ...userData,
    profileImage: memberProfile?.profileImage || '/images/default-avatar.png',
    selectedTopics,
    accessLevel: userData.accessLevel,
    accessLevelLabel
  },
  // 👇 add this line
  mfaStatus,

  memberUnits,
  recentTaggedUnits: await fetchTaggedUnits(id),
  registeredPromptSets,
  promptSet: registeredPromptSets[0] || null,
  memberPromptSchedule: promptSchedules[0] || null,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,
  topicSuggestions,
  memberAccount,
  emailPreferenceLevel
});







        } catch (err) {
            console.error('Error rendering member dashboard:', err);
            return res.status(500).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Error',
                errorMessage: 'An unexpected error occurred. Please try again later.',
            });
        }
    },


  // --- POST /dashboard/member/account/email-preferences ---
  updateEmailPreferences: async (req, res) => {
    try {
      const memberId = req.session?.user?.id;
      if (!memberId) return res.redirect('/auth/login');

      let level = parseInt(req.body.email_preference_level, 10);
      if (![1, 2, 3].includes(level)) level = 1;

      const result = await Member.findByIdAndUpdate(
        memberId,
        { $set: { emailPreferenceLevel: level } },
        { new: false }
      );

      console.log('Member email preferences updated:', memberId, '→ level:', level, 'ok:', !!result);

      // Success page (reuse your leader success partial if you like)
      return res.render('partials/dashboardpartials/emailpreferencessuccess', {
        layout: 'dashboardlayout',
        title: 'Email Preferences Updated',
        emailPreferenceLevel: level,
        dashboard: '/dashboard/member'
      });
    } catch (err) {
      console.error('member.updateEmailPreferences error:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'Could not update email preferences. Please try again.'
      });
    }
  },

  // --- POST /dashboard/member/account/details ---
  updateAccountDetails: async (req, res) => {
    try {
      const memberId = req.session?.user?.id;
      if (!memberId) return res.redirect('/auth/login');

      const { name, email, username } = req.body || {};
      const updates = {};

      // If you have a separate "name" field in Member schema, map it here.
      // Otherwise, continue to use username as the display name.
      if (typeof name === 'string' && name.trim()) updates.username = name.trim();

      if (typeof email === 'string' && email.trim()) updates.email = email.trim();
      if (typeof username === 'string') updates.username = username.trim();

      const changedCount = Object.keys(updates).length;

      if (changedCount) {
        await Member.findByIdAndUpdate(memberId, { $set: updates });
      }

      return res.render('partials/dashboardpartials/accountdetailssuccess', {
        layout: 'dashboardlayout',
        title: 'Account Updated',
        dashboard: '/dashboard/member',
        changedCount,
        name: updates.username,    // what the user sees as name
        email: updates.email,
        username: updates.username // explicit username if different
      });
    } catch (err) {
      console.error('member.updateAccountDetails error:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'Could not update account details. Please try again.'
      });
    }
  }

  };





