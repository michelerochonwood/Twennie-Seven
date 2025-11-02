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
const DashboardSeen = require('../models/dashboard_seen');

 

const toId = (x) => (x && x._id ? x._id : x);

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
'AI in Learning': 'aiinlearning',
    'Project Management': 'projectmanagement',
    'Workplace Culture': 'workplaceculture',
    'The Pareto Principle': 'theparetoprinciple',
    'Career Development in Technical Services': 'careerdevelopmentintechnicalservices',
    'Soft Skills in Technical Environments': 'softskillsintechnicalenvironments',
    'Business Development in Technical Services': 'businessdevelopmentintechnicalservices',
    'Finding Projects Before they Become RFPs': 'findingprojectsbeforetheybecomerfps',
    'Un-Commoditizing Your Services by Delivering What Clients Truly Value': 'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue',
    'Proposal Management': 'proposalmanagement',
    'Proposal Strategy': 'proposalstrategy',
    'Designing a Proposal Process': 'designingaproposalprocess',
    'Conducting Color Reviews of Proposals': 'conductingcolorreviews',
    'Candid Communication': 'candidcommunication',
    'Client Interactions': 'clientinteractions',
'Cross Selling in Multi-Disciplinary Firms': 'crossselling',
'Analytics in Project Management': 'analyticsinprojectmanagement',
'Business Development Metrics': 'businessdevelopmentmetrics',
'Using Lean in Project Management': 'usingleaninprojectmanagement',
'Turning a Project into a Business Development Powerhouse': 'turningaprojectintoabusinessdevelopmentpowerhouse',
'Portfolio and Program Management': 'portfolioandprogrammanagement',
'Making a Proposal Easy to Read, Skim, and Evaluate': 'makingaproposaleasytoreadskimandevaluate',
    'Storytelling in Technical Marketing': 'storytellingintechnicalmarketing',
    'Client Experience': 'clientexperience',
    'Social Media, Advertising, and Other Mysteries': 'socialmediaadvertisingandothermysteries',
    'Pull Marketing': 'pullmarketing',
    'Emotional Intelligence': 'emotionalintelligence',
    'People Before Profit': 'peoplebeforeprofit',
    'Non-Technical Roles in Technical Environments': 'nontechnicalrolesintechnicalenvironments',
    'Leadership in Technical Consulting': 'leadershipintechnicalconsulting',
    'Leading Change': 'leadingchange',
    'The Advantage of Failure': 'theadvantageoffailure',
    'Social Entrepreneurship': 'socialentrepreneurship',
    'Employee Experience': 'employeeexperience',
    'Project Management Software': 'projectmanagementsoftware',
    'CRM Platforms': 'crmplatforms',
    'Client Feedback Software': 'clientfeedbacksoftware',
    'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
    'Remote and Hybrid Work': 'remoteandhybridwork',
    'Four Day Work Week': 'fourdayworkweek',
    'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
    'The Power of Purpose': 'thepowerofpurpose',
    'Team Building in Technical Consulting': 'teambuildingintechnicalconsulting',
    'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading'
};

// Mapping topic slugs to their corresponding view filenames
const topicViewMappings = {
    'aiinconsulting': 'single_topic_aiconsulting',
    'aiinlearning': 'single_topic_ailearn',
    'aiinprojectmanagement': 'single_topic_aiprojectmgmt',
    'businessdevelopmentintechnicalservices': 'single_topic_bd',
    'findingprojectsbeforetheybecomerfps': 'single_topic_findingprojects',
    'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue': 'single_topic_uncommoditize',
    'careerdevelopmentintechnicalservices': 'single_topic_careerdev',
    'clientexperience': 'single_topic_clientex',
    'clientfeedbacksoftware': 'single_topic_clientfeedback',
    'conductingcolorreviews': 'single_topic_colorreviews',
    'crmplatforms': 'single_topic_crm',
    'emotionalintelligence': 'single_topic_emotionali',
    'employeeexperience': 'single_topic_employeeex',
    'theadvantageoffailure': 'single_topic_failure',
    'fourdayworkweek': 'single_topic_fourday',
    'leadershipintechnicalconsulting': 'single_topic_leadership',
    'leadingchange': 'single_topic_change',
    'leadinggroupsontwennie': 'single_topic_leadinggroupsontwennie',
    'mentalhealthinconsultingenvironments': 'single_topic_mental',
    'nontechnicalrolesintechnicalenvironments': 'single_topic_nontechnical',
    'candidcommunication': 'single_topic_candid',
    'clientinteractions': 'single_topic_clientinteractions',
'crosssellinginmultidisciplinaryfirms': 'single_topic_crossselling',
'analyticsinprojectmanagement':'single_topic_analytics',
'businessdevelopmentmetrics': 'single_topic_bdmetrics',
'usingleaninprojectmanagement': 'single_topic_usingleaninprojectmanagement',
'turningaprojectintoabusinessdevelopmentpowerhouse': 'single_topic_bdpowerhouse',
'portfolioandprogrammanagement': 'single_topic_portfolio',
'makingaproposaleasytoreadskimandevaluate': 'single_topic_readskim',
    'theparetoprinciple': 'single_topic_pareto',
    'peoplebeforeprofit': 'single_topic_peoplebefore',
    'thepowerofplayintheworkplace': 'single_topic_play',
    'projectmanagementsoftware': 'single_topic_pmsoftware',
    'projectmanagement': 'single_topic_projectmgmt',
    'proposalmanagement': 'single_topic_proposalmgmt',
    'proposalstrategy': 'single_topic_proposalstrat',
    'designingaproposalprocess': 'single_topic_proposalprocess',
    'pullmarketing': 'single_topic_pullmarketing',
    'remoteandhybridwork': 'single_topic_remote',
    'socialentrepreneurship': 'single_topic_social',
    'socialmediaadvertisingandothermysteries': 'single_topic_socialmedia',
    'softskillsintechnicalenvironments': 'single_topic_softskills',
    'storytellingintechnicalmarketing': 'single_topic_storytelling',
    'teambuildinginconsulting': 'single_topic_teambuilding',
    'tipsandtricksforproposalproofreading': 'single_topic_proofreading',
    'thepowerofpurpose': 'single_topic_purpose',
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
  const psId = toId(promptSetId); // coerce doc → id
  let targetDate = null;

  const registration = await PromptSetRegistration.findOne({ memberId, promptSetId: psId });
  if (registration) {
    targetDate = registration.targetCompletionDate;
  }

  if (!targetDate) {
    console.warn(`No target date found for member ${memberId} and promptSetId ${psId}`);
    return null;
  }

  const today = new Date();
  targetDate = new Date(targetDate);
  const remainingDays = Math.max(0, Math.ceil((targetDate - today) / (1000 * 60 * 60 * 24)));

  // Prompt0 + Prompts 1–20, to match group member logic
  const totalPrompts = 21;

  const progress = await PromptSetProgress.findOne({ memberId, promptSetId: psId });
  const completedCount = progress?.completedPrompts?.length || 0;
  const remainingPrompts = Math.max(0, totalPrompts - completedCount);

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

let registeredPromptSets = [];
let promptSchedules = [];
let currentPromptSets = [];
let formattedCompletedSets = [];
let promptSet = null;
let memberPromptSchedule = null;

// ---------- PROMPT SETS (mirror group-member behavior) ----------
const memberRegistrations = await PromptSetRegistration
  .find({ memberId: id })
  .populate('promptSetId');

const TOTAL_PROMPTS = 21; // Prompt0 + 1..20

// Active prompt cards (exclude completed)
await Promise.all(
  memberRegistrations.map(async (registration) => {
    const psId = toId(registration.promptSetId);
    const promptSetDoc =
      registration.promptSetId && registration.promptSetId.promptset_title
        ? registration.promptSetId
        : await PromptSet.findById(psId);

    if (!promptSetDoc) return;

    // Exclude completed
    const completed = await PromptSetCompletion.findOne({ memberId: id, promptSetId: psId });
    if (completed) return;

    const progress = await PromptSetProgress.findOne({ memberId: id, promptSetId: psId });
    const currentPromptIndex = Number.isInteger(progress?.currentPromptIndex) ? progress.currentPromptIndex : 0;

    const headlineKey = `prompt_headline${currentPromptIndex}`;
    const promptKey   = `Prompt${currentPromptIndex}`;

    registeredPromptSets.push({
      registrationId: registration._id,
      promptSetId: psId.toString(),
      promptSetTitle: promptSetDoc.promptset_title,
      frequency: registration.frequency || promptSetDoc.suggested_frequency,
      mainTopic: promptSetDoc.main_topic,
      purpose: promptSetDoc.purpose,
      promptHeadline: promptSetDoc[headlineKey] || 'No headline found',
      promptText:     promptSetDoc[promptKey]   || 'No prompt text found',
      promptIndex: currentPromptIndex,
      hasStarted: !!progress
    });

    // Schedule for this set
    promptSchedules.push(await getPromptSchedule(id, psId));
  })
);

const completedRecords = await PromptSetCompletion
  .find({ memberId: id })
  .populate('promptSetId');

const completedIds = new Set(
  completedRecords.map(r => r.promptSetId?._id?.toString()).filter(Boolean)
);

// Completed sets (for the table)
// ---------- CURRENT PROMPT SETS (registration-anchored, mirrors group-member) ----------
{
  const currentByPsId = new Map();

  await Promise.all(
    memberRegistrations.map(async (registration) => {
      const psId = toId(registration.promptSetId);
      if (!psId) return;

      // Exclude completed sets
      if (completedIds.has(String(psId))) return;

      // Use populated doc if available, otherwise fetch
      const psDoc = registration.promptSetId && registration.promptSetId.promptset_title
        ? registration.promptSetId
        : await PromptSet.findById(psId);

      if (!psDoc) return;

      // Pull progress for THIS registration
      const prog = await PromptSetProgress.findOne({ memberId: id, promptSetId: psId });

      // ✅ Use completed count (what your SVGs expect)
      const completedCount = Array.isArray(prog?.completedPrompts)
        ? prog.completedPrompts.length
        : 0;

      const progressPct = Math.round((completedCount / TOTAL_PROMPTS) * 100);

      if (!currentByPsId.has(String(psId))) {
        currentByPsId.set(String(psId), {
          promptSetId: String(psId),
          promptSetTitle: psDoc.promptset_title,
          frequency: psDoc.suggested_frequency,
          progress: `${progressPct}%`,
          targetCompletionDate: psDoc.target_completion_date || 'Not Set',
          promptIndex: completedCount, // <- drives your pie & caption
        });
      }
    })
  );

  currentPromptSets = Array.from(currentByPsId.values())
    .sort((a, b) => a.promptSetTitle.localeCompare(b.promptSetTitle));
}


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
/* ---------- SAFE TOPICS (member’s own topics; may be unset) ---------- */
function mbBuildTopicObj(title) {
  if (!title) {
    return {
      title: null,
      subtopics: [],
      slug: 'pick-a-topic',
      viewName: null,
      placeholder: true
    };
  }
  const slug = topicMappings[title] || "unknown-topic";
  return {
    title,
    subtopics: getSubtopics(title),
    slug,
    viewName: topicViewMappings[slug] || "not_found",
    placeholder: false
  };
}

const memberTopics = (userData && typeof userData.topics === 'object') ? userData.topics : {};

const selectedTopics = {
  topic1: mbBuildTopicObj(memberTopics.topic1 || null),
  topic2: mbBuildTopicObj(memberTopics.topic2 || null),
  topic3: mbBuildTopicObj(memberTopics.topic3 || null)
};

const topicsEmpty =
  !selectedTopics.topic1.title &&
  !selectedTopics.topic2.title &&
  !selectedTopics.topic3.title;

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

const memberCounts = {
  prompts:  (registeredPromptSets || []).length,          // registered prompt sets
  progress: (formattedCompletedSets || []).length,        // completed sets
  library:  (memberUnits || []).length,                   // my contributed units (+ upcoming appended above)
  tagged:   (memberTaggedUnits || []).length              // tags I created
};

// ---------- NEW: tab counts + baseline + badges (member) ----------


// Load/create seen doc for this member
let seenDocMember = await DashboardSeen.findOne({ userId: id, role: 'member' });

if (!seenDocMember) {
  // First time: baseline so no dots on first render
  seenDocMember = new DashboardSeen({ userId: id, role: 'member', tabs: new Map() });
  for (const [key, val] of Object.entries(memberCounts)) {
    seenDocMember.tabs.set(key, { count: val, seenAt: new Date() });
  }
  await seenDocMember.save();
} else {
  // If a new tab key appears later, baseline it
  let updated = false;
  for (const [key, val] of Object.entries(memberCounts)) {
    if (!seenDocMember.tabs?.has(key)) {
      seenDocMember.tabs.set(key, { count: val, seenAt: new Date() });
      updated = true;
    }
  }
  if (updated) await seenDocMember.save();
}

// Compute badges: show dot ONLY if current > lastSeen
const memberBadges = {};
for (const [key, val] of Object.entries(memberCounts)) {
  const last = seenDocMember.tabs?.get(key)?.count ?? val; // default = no dot
  memberBadges[key] = val > last;
}

console.log('Member currentPromptSets (for progress):', currentPromptSets);

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
  memberCounts,
  memberBadges,
  mfaStatus,

  memberUnits,
  recentTaggedUnits: await fetchTaggedUnits(id),

  // prompts
  registeredPromptSets,
  promptSet,
  memberPromptSchedule,
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





