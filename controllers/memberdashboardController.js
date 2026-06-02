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
const mongoose = require('mongoose');
const ArchivedUnit = require('../models/archivedUnit');

 

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

    const unitMap = {
      article: [],
      video: [],
      promptset: [],
      interview: [],
      exercise: [],
      template: [],
      upcoming: []
    };

    const tagLookup = new Map(); // key: `${itemId}-${unitType}` => tagId

    tags.forEach(tag => {
      (tag.associatedUnits || []).forEach(({ item, unitType }) => {
        if (unitMap[unitType]) {
          unitMap[unitType].push(item.toString());
          tagLookup.set(`${item.toString()}-${unitType}`, tag._id.toString());
        }
      });
    });

    const [articles, videos, promptSets, interviews, exercises, templates, upcomings] = await Promise.all([
      Article.find({ _id: { $in: unitMap.article } }).lean(),
      Video.find({ _id: { $in: unitMap.video } }).lean(),
      PromptSet.find({ _id: { $in: unitMap.promptset } }).lean(),
      Interview.find({ _id: { $in: unitMap.interview } }).lean(),
      Exercise.find({ _id: { $in: unitMap.exercise } }).lean(),
      Template.find({ _id: { $in: unitMap.template } }).lean(),
      Upcoming.find({ _id: { $in: unitMap.upcoming } }).lean()
    ]);

    const buildViewPath = (type, id) => {
      switch (type) {
        case 'article':
          return `/unitviews/articles/view/${id}`;
        case 'video':
          return `/unitviews/videos/view/${id}`;
        case 'promptset':
          return `/unitviews/promptsets/view/${id}`;
        case 'interview':
          return `/unitviews/interviews/view/${id}`;
        case 'exercise':
          return `/unitviews/exercises/view/${id}`;
        case 'template':
          return `/unitviews/templates/view/${id}`;
        case 'upcoming':
          return `/unitviews/upcomings/view/${id}`;
        default:
          return '#';
      }
    };

    const tagResult = (units, type, titleField) =>
      units.map(unit => ({
        unitType: type,
        title: unit[titleField] || `Untitled ${type}`,
        mainTopic: unit.main_topic || "No topic",
        _id: unit._id,
        tagId: tagLookup.get(`${unit._id.toString()}-${type}`),
        viewPath: buildViewPath(type, unit._id)
      }));

    return [
      ...tagResult(articles, 'article', 'article_title'),
      ...tagResult(videos, 'video', 'video_title'),
      ...tagResult(promptSets, 'promptset', 'promptset_title'),
      ...tagResult(interviews, 'interview', 'interview_title'),
      ...tagResult(exercises, 'exercise', 'exercise_title'),
      ...tagResult(templates, 'template', 'template_title'),
      ...tagResult(upcomings, 'upcoming', 'title')
    ];

  } catch (error) {
    console.error("❌ Error fetching tagged units:", error);
    return [];
  }
}



const topicMappings = {
  'AI in Adult Learning': 'aiinadultlearning',
  'AI in Consulting': 'aiinconsulting',
  'AI in Project Management': 'aiinprojectmanagement',
  'Candid Communication': 'candidcommunication',
  'Career Development in Technical Services': 'careerdevelopmentintechnicalservices',
  'Client Experience': 'clientexperience',
  'Client Feedback Software': 'clientfeedbacksoftware',
  'Client Interactions': 'clientinteractions',
  'Closing a Project Strategically': 'closingaprojectstrategically',
  'Competitor Intelligence A License to Differentiate': 'competitorintelligencealicensetodifferentiate',
  'Conducting Color Reviews of Proposals': 'conductingcolorreviewsofproposals',
  'Conducting Market Research': 'conductingmarketresearch',
  'CRM Software': 'crmsoftware',
  'Creativity and Innovation': 'creativityandinnovation',
  'Cross Selling in Multi-Disciplinary Firms': 'crosssellinginmultidisciplinaryfirms',
  'Cures for Operational Headaches': 'curesforoperationalheadaches',
  'Designing a Proposal Process': 'designingaproposalprocess',
  'Emotional Intelligence': 'emotionalintelligence',
  'Employee Experience': 'employeeexperience',
  'Finding Projects Before they Become RFPs': 'findingprojectsbeforetheybecomerfps',
  'Integrated Project Delivery or IPD': 'integratedprojectdelivery',
  'Leadership in Technical Consulting': 'leadershipintechnicalconsulting',
  'Leading Change': 'leadingchange',
  'Leading Groups on Twennie': 'leadinggroupsontwennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate': 'makingaproposaleasytoreadskimandevaluate',
  'Making Safety a Part of Your Culture': 'makingsafetyapartofyourculture',
  'Managing Scope So It Doesnt Manage You': 'managingscopesoitdoesntmanageyou',
  'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
  'Never Let Good Data Get Away Business Development': 'neverletgooddatagetawaybusinessdevelopment',
  'Never Let Good Data Get Away Project Management': 'neverletgooddatagetawayprojectmanagement',
  'Non-Technical Roles in Technical Environments': 'nontechnicalrolesintechnicalenvironments',
  'People Before Profit': 'peoplebeforeprofit',
  'Program Management': 'programmanagement',
  'Project Management': 'projectmanagement',
  'Project Management Software': 'projectmanagementsoftware',
  'Proposal Management': 'proposalmanagement',
  'Proposal Strategy': 'proposalstrategy',
  'Pull Marketing': 'pullmarketing',
  'Pursuing the Right Projects for Your Firm and Your Team': 'pursuingtherightprojects',
  'Remote and Hybrid Work': 'remoteandhybridwork',
  'Rescuing a Project That Has Gone Off the Rails': 'rescuingaprojectthathasgoneofftherails',
  'Risk Management': 'riskmanagement',
  'Social Entrepreneurship': 'socialentrepreneurship',
  'Social Media, Advertising, and Other Mysteries': 'socialmediaadvertisingandothermysteries',
  'Soft Skills in Technical Environments': 'softskillsintechnicalenvironments',
  'Storytelling in Technical Marketing': 'storytellingintechnicalmarketing',
  'Team Building in Technical Consulting': 'teambuilding',
  'The Advantage of Failure': 'theadvantageoffailure',
  'The First 10 Days of a Project': 'thefirst10daysofaproject',
  'The Pareto Principle': 'theparetoprinciple',
  'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
  'The Power of Purpose': 'thepowerofpurpose',
  'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading',
  'Turning a Project into a Business Development Powerhouse': 'turningaprojectintoabusinessdevelopmentpowerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value': 'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue',
  'Using Lean in Project Management': 'usingleaninprojectmanagement',
  'When the Workload is Light': 'whentheworkloadislight',
  'Workplace Culture': 'workplaceculture'


};

// Mapping topic slugs to their corresponding view filenames
const topicViewMappings = {
  'aiinadultlearning': 'single_topic_ailearn',
  'aiinconsulting': 'single_topic_aiconsulting',
  'aiinprojectmanagement': 'single_topic_aiprojectmgmt',
  'candidcommunication': 'single_topic_candid',
  'careerdevelopmentintechnicalservices': 'single_topic_careerdev',
  'clientexperience': 'single_topic_clientex',
  'clientfeedbacksoftware': 'single_topic_clientfeedback',
  'clientinteractions': 'single_topic_clientinteractions',
  'closingaprojectstrategically': 'single_topic_closing',
  'competitorintelligencealicensetodifferentiate': 'single_topic_differentiate',
  'conductingcolorreviews': 'single_topic_colorreviews',
  'conductingmarketresearch': 'single_topic_research',
  'creativityandinnovation': 'single_topic_creativity',
  'crosssellinginmultidisciplinaryfirms': 'single_topic_crossselling',
  'crmplatforms': 'single_topic_crm',
  'creativityandinnovation': 'single_topic_creativity',
  'curesforoperationalheadaches': 'single_topic_operational',
  'designingaproposalprocess': 'single_topic_proposalprocess',
  'emotionalintelligence': 'single_topic_emotionali',
  'employeeexperience': 'single_topic_employeeex',
  'findingprojectsbeforetheybecomerfps': 'single_topic_findingprojects',
  'integratedprojectdelivery': 'single_topic_integrated',
  'leadershipintechnicalconsulting': 'single_topic_leadership',
  'leadingchange': 'single_topic_change',
  'leadinggroupsontwennie': 'single_topic_leadinggroupsontwennie',
  'makingaproposaleasytoreadskimandevaluate': 'single_topic_readskim',
  'makingsafetyapartofyourculture': 'single_topic_safety',
  'managingscopesoitdoesntmanageyou': 'single_topic_managingscope',
  'mentalhealthinconsultingenvironments': 'single_topic_mental',
  'neverletgooddatagetawayprojectmanagement': 'single_topic_datapm',
  'neverletgooddatagetawaybusinessdevelopment': 'single_topic_databd',
  'nontechnicalrolesintechnicalenvironments': 'single_topic_nontechnical',
  'peoplebeforeprofit': 'single_topic_peoplebefore',
  'programmanagement': 'single_topic_program',
  'projectmanagement': 'single_topic_projectmgmt',
  'projectmanagementsoftware': 'single_topic_pmsoftware',
  'proposalmanagement': 'single_topic_proposalmgmt',
  'proposalstrategy': 'single_topic_proposalstrat',
  'pullmarketing': 'single_topic_pullmarketing',
  'pursuingtherightprojects': 'single_topic_pursuing',
  'remoteandhybridwork': 'single_topic_remote',
  'rescuingaprojectthathasgoneofftherails': 'single_topic_rescuing',
  'riskmanagement': 'single_topic_riskmanagement',
  'socialentrepreneurship': 'single_topic_social',
  'socialmediaadvertisingandothermysteries': 'single_topic_socialmedia',
  'softskillsintechnicalenvironments': 'single_topic_softskills',
  'storytellingintechnicalmarketing': 'single_topic_storytelling',
  'teambuildingintechnicalconsulting': 'single_topic_teambuilding',
  'theadvantageoffailure': 'single_topic_failure',
  'thefirst10daysofaproject': 'single_topic_first10days',
  'theparetoprinciple': 'single_topic_pareto',
  'thepowerofplayintheworkplace': 'single_topic_play',
  'thepowerofpurpose': 'single_topic_purpose',
  'tipsandtricksforproposalproofreading': 'single_topic_proofreading',
  'turningaprojectintoabusinessdevelopmentpowerhouse': 'single_topic_bdpowerhouse',
  'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue': 'single_topic_uncommoditize',
  'usingleaninprojectmanagement': 'single_topic_usingleaninprojectmanagement',
  'whentheworkloadislight': 'single_topic_workloadlight',
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
      const memberOid = new mongoose.Types.ObjectId(String(id)); // <-- ADD
      if (!id) return res.redirect('/auth/login');

const archivedUnits = await ArchivedUnit.find({
  archivedBy: id
})
  .select('tagId unitId unitType assignedToMember archiveScope')
  .lean();

const archivedKeySet = new Set(
  archivedUnits.map(a => {
    const assigneeKey = a.assignedToMember ? String(a.assignedToMember) : 'self';
    return `${String(a.tagId)}-${String(a.unitId)}-${assigneeKey}`;
  })
);

const archivedCompletedPromptSetIds = new Set(
  archivedUnits
    .filter(a =>
      a.unitType === 'promptset' &&
      String(a.assignedToMember || '') === String(id)
    )
    .map(a => String(a.unitId))
);

function isArchivedDashboardItem(tagId, unitId, assignedToId = null) {
  const assigneeKey = assignedToId ? String(assignedToId) : 'self';
  return archivedKeySet.has(`${String(tagId)}-${String(unitId)}-${assigneeKey}`);
}

function isArchivedCompletedPromptSet(promptSetId) {
  if (!promptSetId) return false;
  return archivedCompletedPromptSetIds.has(String(promptSetId));
}

      const userData = await Member.findById(id)
        .select('name username email emailPreferenceLevel profileImage professionalTitle organization topics accessLevel mfa.enabled mfa.method mfa.recoveryCodes mfa.updatedAt')
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
  .find({ memberId: memberOid }) // <-- memberOid
  .populate('promptSetId');

const TOTAL_PROMPTS = 21; // Prompt0 + 1..20

// Active prompt cards (exclude completed)
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
    const completed = await PromptSetCompletion.findOne({ memberId: memberOid, promptSetId: psId });
    if (completed) return;

    const progress = await PromptSetProgress.findOne({ memberId: memberOid, promptSetId: psId });
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

      // 🔑 Only consider “started” once Prompt 1 begins
      hasStarted: currentPromptIndex > 0
    });

    // Schedule for this set
    promptSchedules.push(await getPromptSchedule(id, psId));
  })
);


// ✅ Select the first active prompt set & schedule for the "registered prompt sets" tab
promptSet = registeredPromptSets.length ? registeredPromptSets[0] : null;
memberPromptSchedule = promptSchedules.length ? promptSchedules[0] : null;

// 🧪 Optional sanity log (remove later)
console.log('🧪 promptSet selected for tab:', promptSet && {
  id: promptSet.promptSetId,
  title: promptSet.promptSetTitle,
  promptIndex: promptSet.promptIndex,
  hasStarted: promptSet.hasStarted
});
console.log('🧪 memberPromptSchedule selected:', memberPromptSchedule);


const completedRecords = await PromptSetCompletion
  .find({ memberId: memberOid })   // <-- use memberOid
  .populate('promptSetId');

const completedIds = new Set(
  completedRecords.map(r => r.promptSetId?._id?.toString()).filter(Boolean)
);

// Completed sets (for the table)
// ------------- CURRENT sets (progress overview) -------------
// Registration-anchored, like group-member; drives the PIE and caption
{
  const currentByPsId = new Map();

  await Promise.all(
    memberRegistrations.map(async (registration) => {
      const psId = toId(registration.promptSetId);
      if (!psId) return;

      // Exclude sets already completed
      if (completedIds.has(String(psId))) return;

      // Use populated doc if available, otherwise fetch
      const psDoc = registration.promptSetId && registration.promptSetId.promptset_title
        ? registration.promptSetId
        : await PromptSet.findById(psId);

      if (!psDoc) return;

      // Progress row for THIS registration
      const prog = await PromptSetProgress.findOne({ memberId: memberOid, promptSetId: psId });  // <-- memberOid
      const completedCount = Array.isArray(prog?.completedPrompts) ? prog.completedPrompts.length : 0;
      const progressPct = Math.round((completedCount / TOTAL_PROMPTS) * 100);

      // Insert once per prompt set
      if (!currentByPsId.has(String(psId))) {
        currentByPsId.set(String(psId), {
          promptSetId: String(psId),
          promptSetTitle: psDoc.promptset_title,
          frequency: psDoc.suggested_frequency,
          progress: `${progressPct}%`,
          targetCompletionDate: psDoc.target_completion_date || 'Not Set',

          // 🔑 This drives the filename /promptprogress/promptprogress{n}-{this.promptIndex}.svg
          // and the caption "you have completed X prompts..."
          promptIndex: completedCount
        });
      }
    })
  );

  currentPromptSets = Array.from(currentByPsId.values())
    .sort((a, b) => a.promptSetTitle.localeCompare(b.promptSetTitle));

    console.log('🧪 EMIT currentPromptSets:', JSON.stringify(currentPromptSets, null, 2));
}

// ------------- COMPLETED (mapped for view) -------------
// (Needed for memberCounts.progress and the completed list)
formattedCompletedSets = completedRecords
  .filter(record => {
    const promptSetId = record.promptSetId?._id?.toString();
    return !isArchivedCompletedPromptSet(promptSetId);
  })
  .map(record => ({
    completionId: record._id?.toString() || '',
    promptSetId: record.promptSetId?._id?.toString() || '',
    assignedToId: id,

    promptSetTitle: record.promptSetId?.promptset_title || 'Unknown Title',
    frequency: record.promptSetId?.suggested_frequency,
    mainTopic: record.promptSetId?.main_topic || 'No Topic',
    completedAt: record.completedAt ? new Date(record.completedAt).toDateString() : 'Unknown Date',
    badge: record.earnedBadge
  }));

            // ✅ Fetch tagged and contributed units
// ✅ Fetch tagged and contributed units
const memberTaggedUnitsRaw = await fetchTaggedUnits(id);

const memberTaggedUnits = memberTaggedUnitsRaw.filter(u =>
  !isArchivedDashboardItem(u.tagId, u._id)
);

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

const emailPreferenceLevel = [1, 2].includes(Number(userData?.emailPreferenceLevel))
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

const displayName =
  (userData?.name && userData.name.trim()) ? userData.name.trim() :
  (memberProfile?.name && memberProfile.name.trim && memberProfile.name.trim()) ? memberProfile.name.trim() :
  (userData?.username || 'Member');

return res.render("member_dashboard", {
  layout: "dashboardlayout",
  title: "Member Dashboard",
  csrfToken: req.csrfToken(),
  member: {
    ...userData,
      name: displayName, // <-- ensure sidebar {{member.name}} has a value
    profileImage: memberProfile?.profileImage || '/images/default-avatar.png',
    selectedTopics,
    accessLevel: userData.accessLevel,
    accessLevelLabel
  },
  memberCounts,
  memberBadges,
  mfaStatus,

  memberUnits,
recentTaggedUnits: memberTaggedUnits,

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
      if (![1, 2].includes(level)) level = 1;

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
  },

  markMemberTabSeen: async (req, res) => {
  try {
    const memberId = req.session?.user?.id || req.user?._id?.toString();

    if (!memberId) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    const tabKey = req.body?.tab || req.body?.tabKey;
    const currentCount = req.body?.count ?? req.body?.currentCount;

    if (!tabKey) {
      return res.status(400).json({ ok: false, error: 'missing tab key' });
    }

    let seenDoc = await DashboardSeen.findOne({
      userId: memberId,
      role: 'member'
    });

    if (!seenDoc) {
      seenDoc = new DashboardSeen({
        userId: memberId,
        role: 'member',
        tabs: new Map()
      });
    }

    seenDoc.tabs.set(tabKey, {
      count: Number(currentCount) || 0,
      seenAt: new Date()
    });

    await seenDoc.save();

    return res.json({ ok: true });
  } catch (e) {
    console.error('markMemberTabSeen error:', e);
    return res.status(500).json({ ok: false });
  }
}

  };





