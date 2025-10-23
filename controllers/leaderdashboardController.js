const GroupMember = require('../models/member_models/group_member');
const Leader = require('../models/member_models/leader');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const Tag = require('../models/tag');
const path = require('path'); // ✅ Fix for "ReferenceError: path is not defined"
const fs = require('fs'); // ✅ Ensure file system functions work
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const Note = require('../models/notes/notes');
const TopicSuggestion = require('../models/topic/topic_suggestion');
const Upcoming = require('../models/unit_models/upcoming');
const DashboardSeen = require('../models/dashboard_seen');
const GroupProfile = require('../models/profile_models/group_profile');


function getModelByUnitType(type) {
  switch (type) {
    case 'article':   return Article;
    case 'video':     return Video;
    case 'interview': return Interview;
    case 'exercise':  return Exercise;
    case 'template':  return Template;
    case 'upcoming':  return Upcoming;
    default:          return null;
  }
}




async function resolveAuthorById(authorId) {
    try {
        // Leader profile
        let profile = await LeaderProfile.findOne({ leaderId: authorId }).select('profileImage name');
        if (profile) return { name: profile.name || 'Leader', image: profile.profileImage || '/images/default-avatar.png' };

        // Group member profile
        profile = await GroupMemberProfile.findOne({ groupMemberId: authorId }).select('profileImage name');
        if (profile) return { name: profile.name || 'Group Member', image: profile.profileImage || '/images/default-avatar.png' };
    } catch (err) {
        console.error('resolveAuthorById failed:', err);
    }

    return { name: 'Unknown Author', image: '/images/default-avatar.png' };
}

function pickAuthorId(u) {
  // covers: { author: { id } }, { author: ObjectId }, createdBy, submittedBy
  return u?.author?.id || u?.author || u?.createdBy || u?.submittedBy || null;
}


async function fetchTaggedUnits(userId) {
  try {
    // Only tags CREATED by this leader
    const tags = await Tag.find({ createdBy: userId }).lean();
    if (!tags.length) return [];

    // Build a fetch list by unit type
    const unitMap = {
      article:   [],
      video:     [],
      promptset: [],
      interview: [],
      exercise:  [],
      template:  [],
      upcoming: []
    };

    // Map key → tag (so we can read assignedTo length per unit)
    const tagByKey = new Map(); // `${itemId}-${unitType}` → tag doc

    for (const tag of tags) {
      for (const { item, unitType } of tag.associatedUnits || []) {
        if (unitMap[unitType]) {
          const key = `${item.toString()}-${unitType}`;
          unitMap[unitType].push(item.toString());
          tagByKey.set(key, tag);
        }
      }
    }

    // Fetch units
    const [articles, videos, promptSets, interviews, exercises, templates] = await Promise.all([
      Article.find({ _id: { $in: unitMap.article } }).lean(),
      Video.find({ _id: { $in: unitMap.video } }).lean(),
      PromptSet.find({ _id: { $in: unitMap.promptset } }).lean(),
      Interview.find({ _id: { $in: unitMap.interview } }).lean(),
      Exercise.find({ _id: { $in: unitMap.exercise } }).lean(),
      Template.find({ _id: { $in: unitMap.template } }).lean()
    ]);

    const tagResult = (units, type, titleField) =>
      units.map(unit => {
        const key = `${unit._id.toString()}-${type}`;
        const tag = tagByKey.get(key);
        const assignedCount = Array.isArray(tag?.assignedTo) ? tag.assignedTo.length : 0;
        return {
          unitType: type,
          title: unit[titleField] || `Untitled ${type}`,
          mainTopic: unit.main_topic || "No topic",
          _id: unit._id,
          tagId: tag?._id?.toString() || null,
          assignedCount // 👈 0 = self-tag, >0 = assignment tag
        };
      });

    return [
      ...tagResult(articles, 'article',   'article_title'),
      ...tagResult(videos,   'video',     'video_title'),
      ...tagResult(promptSets,'promptset','promptset_title'),
      ...tagResult(interviews,'interview','interview_title'),
      ...tagResult(exercises,'exercise',  'exercise_title'),
      ...tagResult(templates,'template',  'template_title')
    ];
  } catch (error) {
    console.error("❌ Error fetching tagged units for leader:", error);
    return [];
  }
}



async function buildLeaderAssignedUnits(leaderId) {
  const assignedTags = await Tag.find({
    createdBy: leaderId,
    assignedTo: { $exists: true, $ne: [] },
  }).lean();

  const leaderAssignedUnits = [];
  const leaderAssignmentsOpen = [];
  const leaderAssignmentsCompleted = [];

  for (const tag of assignedTags) {
    // Flat open/completed rows (optional, handy for counts/mini tables)
    for (const a of (tag.assignedTo || [])) {
      const row = {
        tagId: tag._id.toString(),
        tagName: tag.name,
        memberId: a.member?.toString(),
        instructions: a.instructions || '',
        completedAt: a.completedAt || null
      };
      if (row.completedAt) leaderAssignmentsCompleted.push(row);
      else leaderAssignmentsOpen.push(row);
    }

    // Per-unit cards for the partial
    for (const { item, unitType } of tag.associatedUnits || []) {
      if (unitType === 'promptset' || unitType === 'prompt') continue;

      const Model = getModelByUnitType(unitType);
      if (!Model) continue;

      const unit = await Model.findById(item).lean();
      if (!unit) continue;

      for (const assignee of tag.assignedTo || []) {
        const member = await GroupMember.findById(assignee.member).select('name').lean();
        if (!member) continue;

leaderAssignedUnits.push({
  _id: item,
  unitType,
  title:
    unit.article_title ||
    unit.video_title ||
    unit.interview_title ||
    unit.exercise_title ||
    unit.template_title ||
    "Untitled",
  mainTopic: unit.main_topic || "No topic",

  // ✅ add this line so the partial can delete the tag:
  tagId: tag._id.toString(),

  assignedTo: {
    _id: assignee.member?.toString(),
    name: member.name,
    instructions: assignee.instructions || '',
    completedAt: assignee.completedAt || null,
  }
});
      }
    }
  }

  return { leaderAssignedUnits, leaderAssignmentsOpen, leaderAssignmentsCompleted };
}


// ---- helpers for "assigned prompt sets" cards ----
function fmtDate(d) {
  if (!d) return 'Not set';
  const dd = new Date(d);
  if (Number.isNaN(dd.getTime())) return 'Not set';
  return dd.toLocaleDateString('en-CA', { year: 'numeric', month: 'short', day: '2-digit' });
}

/**
 * Build cards for the dashboard's "assigned prompt sets" section.
 * One card per (assignment x member) to match the partial.
 * Uses your schema fields exactly: groupLeaderId, assignedMemberIds[], frequency, leaderNotes, targetCompletionDate.
 */
async function buildAssignedPromptCards(leaderId) {
  // 1) get all prompt-set assignments created by this leader
  const assignments = await AssignPromptSet.find({ groupLeaderId: leaderId }).lean();
  if (!assignments.length) return [];

  // 2) collect unique IDs we’ll need to hydrate in batches
  const promptSetIds = new Set();
  const memberIds = new Set();

  for (const a of assignments) {
    if (a.promptSetId) promptSetIds.add(a.promptSetId.toString());
    for (const mid of a.assignedMemberIds || []) memberIds.add(mid.toString());
  }

  // 3) hydrate prompt sets + members + member profiles
  const [promptSets, members, profiles] = await Promise.all([
    PromptSet.find({ _id: { $in: [...promptSetIds] } }).lean(),
    GroupMember.find({ _id: { $in: [...memberIds] } }).select('name').lean(),
    GroupMemberProfile.find({ groupMemberId: { $in: [...memberIds] } }).select('groupMemberId profileImage').lean()
  ]);

  const psById = new Map(promptSets.map(ps => [ps._id.toString(), ps]));
  const memberById = new Map(members.map(m => [m._id.toString(), m]));
  const profileByMemberId = new Map(profiles.map(p => [p.groupMemberId.toString(), p]));

  // 4) build cards (and fetch progress per member/prompt-set)
  const cards = [];
  for (const a of assignments) {
    const ps = psById.get(a.promptSetId?.toString());
    if (!ps) continue;

    const target = a.targetCompletionDate || ps.target_completion_date || null;
    const now = new Date();

    // one card per assignee
    for (const memberId of a.assignedMemberIds || []) {
      const mid = memberId?.toString();
      const m = memberById.get(mid);
      if (!m) continue;

      const prof = profileByMemberId.get(mid);
      const memberImage = prof?.profileImage || '/images/default-avatar.png';

      const progress = await PromptSetProgress
        .findOne({ memberId: mid, promptSetId: ps._id })
        .select('currentPromptIndex completedPrompts')
        .lean();

      const completedCount = Array.isArray(progress?.completedPrompts) ? progress.completedPrompts.length : 0;
      const progressPercent = Math.min(100, Math.round((completedCount / 20) * 100));
      const currentPromptIndex = Number.isInteger(progress?.currentPromptIndex) ? progress.currentPromptIndex : 0;

      const isCompleted = completedCount >= 20;
      const isOverdue = !isCompleted && target && new Date(target) < now;
      const hasStarted = !isCompleted && completedCount > 0;

      let status = 'assigned';
      let statusLabel = 'assigned';
      if (isCompleted) {
        status = 'completed';
        statusLabel = 'completed';
      } else if (isOverdue) {
        status = 'overdue';
        statusLabel = 'overdue';
      } else if (hasStarted) {
        status = 'inprogress';
        statusLabel = 'in progress';
      }

      cards.push({
        assignmentId: a._id.toString(),                    // used by your unassign form
        promptSetId: ps._id.toString(),
        promptSetTitle: ps.promptset_title,
        mainTopic: ps.main_topic || 'No topic',
        frequency: a.frequency || ps.suggested_frequency || 'weekly',
        targetCompletionDate: fmtDate(target),

        memberId: mid,
        memberName: m.name,
        memberImage,

        currentPromptIndex,
        progressPercent,

        status,
        statusLabel,

        leaderNotes: a.leaderNotes || ''
      });
    }
  }

  // sort by due date string (already formatted). If you prefer strict date sort, sort on Date(target) before formatting.
  return cards.sort((a, b) => a.targetCompletionDate.localeCompare(b.targetCompletionDate));
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
    'Leading Groups on Twennie': 'leadinggroupsontwennie',
    'The Advantage of Failure': 'theadvantageoffailure',
    'Social Entrepreneurship': 'socialentrepreneurship',
    'Employee Experience': 'employeeexperience',
    'Project Management Software': 'projectmanagementsoftware',
    'CRM Platforms': 'crmplatforms',
    'Client Feedback Software': 'clientfeedbacksoftware',
    'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
    'Remote and Hybrid Work': 'remoteandhybridwork',
    'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
    'Team Building in Technical Consulting': 'teambuildingintechnicalconsulting',
    'The Power of Purpose': 'thepowerofpurpose',
    'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading'
};

// Mapping topic slugs to their corresponding view filenames
const topicViewMappings = {
    'aiinconsulting': 'single_topic_aiconsulting',
    'aiinadultlearning': 'single_topic_ailearn',
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
    'leadershipintechnicalconsulting': 'single_topic_leadership',
    'leadingchange': 'single_topic_change',
    'leadinggroupsontwennie': 'single_topic_leadinggroupsontwennie',
    'candidcommunication': 'single_topic_candid',
    'clientinteractions': 'single_topic_clientinteractions',
'crosssellinginmultidisciplinaryfirms': 'single_topic_crossselling',
'analyticsinprojectmanagement':'single_topic_analytics',
'businessdevelopmentmetrics': 'single_topic_bdmetrics',
'usingleaninprojectmanagement': 'single_topic_usingleaninprojectmanagement',
'turningaprojectintoabusinessdevelopmentpowerhouse': 'single_topic_bdpowerhouse',
'portfolioandprogrammanagement': 'single_topic_portfolio',
'makingaproposaleasytoreadskimandevaluate': 'single_topic_readskim',
    'mentalhealthinconsultingenvironments': 'single_topic_mental',
    'nontechnicalrolesintechnicalenvironments': 'single_topic_nontechnical',
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
    'teambuildingintechnicalconsulting': 'single_topic_teambuilding',
    'workplaceculture': 'single_topic_workplaceculture',
    'thepowerofpurpose': 'single_topic_purpose',
    'tipsandtricksforproposalproofreading': 'single_topic_proofreading'
};

// Function to resolve unit type
function resolveUnitType(unit) {
    if (unit.article_title) return "Article";
    if (unit.video_title) return "Video";
    if (unit.interview_title) return "Interview";
    if (unit.exercise_title) return "Exercise";
    if (unit.template_title) return "Template";
    if (unit.promptset_title) return "Prompt Set";
    
    // Backup: Use Mongoose model name if available
    return unit.constructor?.modelName || "Unknown";
}


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




async function getLeaderPromptSchedule(leaderId, promptSetId) {
    let targetDate = null;

    // Check for registration or assignment and get the target completion date
    const registration = await PromptSetRegistration.findOne({ memberId: leaderId, promptSetId });
    if (registration) {
        targetDate = registration.targetCompletionDate;
    } else {
        const assignment = await AssignPromptSet.findOne({ assignedMemberId: leaderId, promptSetId });
        if (assignment) {
            targetDate = assignment.targetCompletionDate;
        }
    }

    if (!targetDate) return null; // No target date found

    const today = new Date();
    targetDate = new Date(targetDate);
    const remainingDays = Math.max(0, Math.ceil((targetDate - today) / (1000 * 60 * 60 * 24)));

    // Fetch progress and determine remaining prompts
    const progress = await PromptSetProgress.findOne({ memberId: leaderId, promptSetId });

    if (!progress) {
  console.warn(`⚠️ No progress found for promptSetId ${registration.promptSetId}. Showing Prompt 0 fallback.`);
  progress = {
    currentPromptIndex: 0,
    completedPrompts: []
  };
}
    const remainingPrompts = progress && progress.completedPrompts ? 21 - progress.completedPrompts.length : 21;

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
    renderLeaderDashboard: async (req, res) => {

        try {
            const { id } = req.session.user;
            console.log("Fetching dashboard for leader:", id);

const userData = await Leader.findById(id)
  .select([
    'groupName',
    'groupLeaderName',
    'groupLeaderEmail',
    'username',
    'emailPreferenceLevel',
    'profileImage',
    'professionalTitle',
    'organization',
    'topics',
    'members',
    // 👇 add MFA fields
    'mfa.enabled',
    'mfa.method',
    'mfa.recoveryCodes',
    'mfa.updatedAt'
  ].join(' '))
  .populate({
    path: 'members',
    model: 'GroupMember',
    select: 'name profileImage professionalTitle isVerified'
  })
  .lean();
  
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
const leaderProfile = await LeaderProfile
  .findOne({ $or: [ { leaderId: id }, { groupId: id } ] })
  .select('profileImage groupImage topics')
  .lean();

  // Pull the group's image from the group profile doc
const groupProfile = await GroupProfile
  .findOne({ groupId: id })
  .select('groupImage')
  .lean();



            // ---- Safe topics (leaders may not have topics on account doc) ----
function buildTopicObj(title) {
  if (!title) {
    return {
      title: null,
      subtopics: [],
      slug: 'pick-a-topic',
      viewName: null,
      placeholder: true
    };
  }
  const slug = topicMappings[title] || 'unknown-topic';
  return {
    title,
    subtopics: getSubtopics(title),
    slug,
    viewName: topicViewMappings[slug] || 'not_found',
    placeholder: false
  };
}

// Prefer profile topics; fall back to legacy leader.topics if present
const profileTopics = (leaderProfile && typeof leaderProfile.topics === 'object') ? leaderProfile.topics : {};
const accountTopics = (userData && typeof userData.topics === 'object') ? userData.topics : {};

const selectedTopics = {
  topic1: buildTopicObj(profileTopics.topic1 || accountTopics.topic1 || null),
  topic2: buildTopicObj(profileTopics.topic2 || accountTopics.topic2 || null),
  topic3: buildTopicObj(profileTopics.topic3 || accountTopics.topic3 || null)
};

const topicsEmpty =
  !selectedTopics.topic1.title &&
  !selectedTopics.topic2.title &&
  !selectedTopics.topic3.title;

// Shim to keep old templates (leader.topics.topic1) from crashing
const leaderTopicsShim = {
  topic1: selectedTopics.topic1.title,
  topic2: selectedTopics.topic2.title,
  topic3: selectedTopics.topic3.title
};


            


            const topicSuggestions = await TopicSuggestion.find({
            suggestedBy: id,
            memberType: 'Leader' // This ensures it's scoped to leaders only

}).sort({ submittedAt: -1 }).lean();

const resolvedGroupMembers = await Promise.all(
  (userData.members || []).map(async (memberDoc) => {
    // plain object for merging
    const m = typeof memberDoc.toObject === 'function' ? memberDoc.toObject() : memberDoc;
    // ✅ use groupMemberId (new schema), not memberId
    const profile = await GroupMemberProfile
      .findOne({ groupMemberId: m._id })
      .select('profileImage')
      .lean();

    return {
      ...m,
      profileImage: profile?.profileImage || '/images/default-avatar.png'
    };
  })
);




            const leader = userData; // ✅ Ensures leader is properly defined before usage
            const leaderGroupMembers = userData.members || []; // ✅ Ensures it's always an array
            // Fetch all group members under this leader
            const leaderGroupMemberIds = leaderGroupMembers.map(member => member._id);

const [
  groupArticles,
  groupVideos,
  groupPromptSets,
  groupInterviews,
  groupExercises,
  groupTemplates,
  groupUpcomings // 👈 NEW
] = await Promise.all([
  Article.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Video.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  PromptSet.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Interview.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Exercise.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Template.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Upcoming.find({ createdBy: { $in: leaderGroupMemberIds } }).lean() // 👈 upcoming uses createdBy
]);
            
let groupMemberUnits = await Promise.all(
  [...groupArticles, ...groupVideos, ...groupPromptSets, ...groupInterviews, ...groupExercises, ...groupTemplates].map(async (unit) => {
    const author = await resolveAuthorById(pickAuthorId(unit));
    return {
      unitType: resolveUnitType(unit),
      title:
        unit.article_title ||
        unit.video_title ||
        unit.promptset_title ||
        unit.interview_title ||
        unit.exercise_title ||
        unit.template_title ||
        "Untitled Unit",
      status: unit.status || "Unknown",
      mainTopic: unit.main_topic || "No topic",
      _id: unit._id,
      author: author.name
    };
  })
);

const gmUpcomingRows = await Promise.all(
  (groupUpcomings || []).map(async (u) => {
    const author = await resolveAuthorById(u.createdBy);
    return {
      unitType: 'upcoming',
      plannedType: u.unit_type,                 // e.g., 'video'
      title: u.title,
      status: u.status || 'in production',
      mainTopic: u.main_topic || 'No topic',
      _id: u._id,
      author: author?.name || 'Group Member',
      projectedRelease: u.projected_release_at
    };
  })
);
            
groupMemberUnits = [...groupMemberUnits, ...gmUpcomingRows];

            if (!userData) {
                throw new Error(`Leader with ID ${id} not found.`);
            }

            console.log("Fetched leader data:", userData);

            const maxGroupSize = 10;
            userData.maxGroupSize = maxGroupSize;

            const leaderRegistrations = await PromptSetRegistration.find({ memberId: id }).populate('promptSetId');
            console.log(`Total prompt sets found for leader ${id}: ${leaderRegistrations.length}`);
            
            let leaderPrompts = [];
            let promptSchedules = [];
            
            // ✅ Fetch prompt progress from the database instead of using session storage
            await Promise.all(
                leaderRegistrations.map(async (registration) => {
                    const promptSet = await PromptSet.findById(registration.promptSetId);
                    if (!promptSet) return;
            
                    const progress = await PromptSetProgress.findOne({ memberId: id, promptSetId: registration.promptSetId });
            
                    const currentPromptIndex = progress?.currentPromptIndex ?? 0; // ✅ Ensure first prompt is always 0
            
                    console.log(`Progress for promptSetId ${registration.promptSetId._id}: ${currentPromptIndex}`);
            
                    const headlineKey = `prompt_headline${currentPromptIndex}`;
                    const promptKey = `Prompt${currentPromptIndex}`;
            
                    const isCompleted = progress?.completedPrompts?.length >= 20;
            
if (!isCompleted) {
  const currentPromptIndex = progress?.currentPromptIndex ?? 0;
  const headlineKey = `prompt_headline${currentPromptIndex}`;
  const promptKey = `Prompt${currentPromptIndex}`;

leaderPrompts.push({
  registrationId: registration._id.toString(), // ✅ this is what the unregister route needs
  promptSetId: registration.promptSetId._id.toString(),
  promptSetTitle: promptSet.promptset_title,
  frequency: registration.frequency,
  mainTopic: promptSet.main_topic,
  purpose: promptSet.purpose,
  promptIndex: currentPromptIndex,
  promptHeadline: promptSet[headlineKey] || "No headline found",
  promptText: promptSet[promptKey] || "No prompt text found"
});

}

            
                    promptSchedules.push(await getLeaderPromptSchedule(id, registration.promptSetId));
                })
            );
            
            console.log("Leader Prompts Data:", JSON.stringify(leaderPrompts, null, 2));
            console.log("Prompt schedules:", JSON.stringify(promptSchedules, null, 2));
            
            // ✅ Fetch prompt set progress from MongoDB (No session-based tracking)

// ✅ First fetch completed prompt sets
const completedRecords = await PromptSetCompletion.find({ memberId: id }).populate('promptSetId');

// ✅ Then fetch in-progress prompt records
const progressRecords = await PromptSetProgress.find({ memberId: id }).populate('promptSetId');

const completedIds = new Set(completedRecords.map(record => record.promptSetId._id.toString()));

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




            

const allLeaderTaggedUnits = await fetchTaggedUnits(id);

// Only self-tags (no assignments) count toward "my tagged units"
const leaderSelfTaggedUnits = allLeaderTaggedUnits.filter(u => u.assignedCount === 0);
const leaderTaggedCountAll = allLeaderTaggedUnits.length;

            const [leaderArticles, leaderVideos, leaderPromptSets, leaderInterviews, leaderExercises, leaderTemplates] = await Promise.all([
                Article.find({ 'author.id': id }),
                Video.find({ 'author.id': id }),
                PromptSet.find({ 'author.id': id }),
                Interview.find({ 'author.id': id }),
                Exercise.find({ 'author.id': id }),
                Template.find({ 'author.id': id }),
            ]);

            const leaderUpcomings = await Upcoming.find({ createdBy: id }).lean();

const leaderUpcomingRows = (leaderUpcomings || []).map((u) => ({
  unitType: 'upcoming',
  plannedType: u.unit_type,                 // e.g., 'video'
  title: u.title,
  status: u.status || 'in production',
  mainTopic: u.main_topic || 'No topic',
  _id: u._id,
  projectedRelease: u.projected_release_at
}));

let leaderUnits = await Promise.all(
  [...leaderArticles, ...leaderVideos, ...leaderPromptSets, ...leaderInterviews, ...leaderExercises, ...leaderTemplates].map(async (unit) => {
    const author = await resolveAuthorById(pickAuthorId(unit));
    return {
      unitType: unit.unitType || unit.constructor?.modelName || 'Unknown',
      title:
        unit.article_title ||
        unit.video_title ||
        unit.promptset_title ||
        unit.interview_title ||
        unit.exercise_title ||
        unit.template_title,
      status: unit.status,
      mainTopic: unit.main_topic,
      _id: unit._id,
      author: author.name
    };
  })
);


      leaderUnits = [...leaderUnits, ...leaderUpcomingRows];      
            

            console.log("All session keys before rendering:", Object.keys(req.session));

            // ✅ Remove session-based prompt tracking (Database handles it now)
            
            // ✅ Ensure we are using `getLeaderPromptSchedule()`
            promptSchedules = await Promise.all(
                leaderRegistrations.map(async (registration) => 
                    getLeaderPromptSchedule(id, registration.promptSetId)
                )
            );
            
            console.log("Updated Leader Prompts Data:", JSON.stringify(leaderPrompts, null, 2));
            console.log("Prompt Schedules:", JSON.stringify(promptSchedules, null, 2));
            


// Now fetch completed prompt set records directly from the PromptSetCompletion collection


// Map the completion records to a formatted array
const formattedCompletedSets = completedRecords.map(record => ({
    promptSetTitle: record.promptSetId.promptset_title,
    frequency: record.promptSetId.suggested_frequency,
    mainTopic: record.promptSetId.main_topic,
    completedAt: record.completedAt ? new Date(record.completedAt).toDateString() : "Unknown Date",
    badge: record.earnedBadge // This should now contain an object with { image, name }
}));

const { leaderAssignedUnits, leaderAssignmentsOpen, leaderAssignmentsCompleted } = await buildLeaderAssignedUnits(id);
// --- Membership tab: derive view flags & user fields for template ---

// 1) Email preference flags (defaults to Level 1 if unset/invalid)
// --- Membership tab: prepare leader account & email preference flags ---
// NOTE: Make sure your earlier Leader.findById(id).select(...) includes
//       `email_preference_level`, `groupLeaderEmail`, and `username`,
//       or the fallbacks below will be used.

// --- Membership tab: prepare leader account & email preference for view ---
// --- Membership tab: prepare leader account & email preference for view ---
const rawPref = userData?.emailPreferenceLevel ?? userData?.email_preference_level;
const emailPreferenceLevel = [1, 2, 3].includes(Number(rawPref)) ? Number(rawPref) : 1;

const leaderAccount = {
  name: userData?.groupLeaderName || 'Leader',
  email: userData?.groupLeaderEmail || '',
  username: userData?.username || ''
};

// ---------- NEW: tab counts + badges ----------
const leaderCounts = {
  group:    (resolvedGroupMembers || []).length,       // my group members
  topics:   (topicSuggestions || []).length,           // my suggested topics
  prompts:  (leaderRegistrations || []).length,        // registered prompt sets
  progress: (formattedCompletedSets || []).length,     // simple monotonic signal
  library:  (leaderUnits || []).length,                // my contributions (incl. upcoming)
  tagged:   leaderTaggedCountAll                       // 👈 all tags I created (self + assignments)
};

// Load/create seen doc for this leader
let seenDocLeader = await DashboardSeen.findOne({ userId: id, role: 'leader' });

if (!seenDocLeader) {
  // First time: baseline all tabs to current counts (no dots on first render)
  seenDocLeader = new DashboardSeen({ userId: id, role: 'leader', tabs: new Map() });
  for (const [key, val] of Object.entries(leaderCounts)) {
    seenDocLeader.tabs.set(key, { count: val, seenAt: new Date() });
  }
  await seenDocLeader.save();
} else {
  // If new tabs were added later, baseline them once
  let updated = false;
  for (const [key, val] of Object.entries(leaderCounts)) {
    if (!seenDocLeader.tabs?.has(key)) {
      seenDocLeader.tabs.set(key, { count: val, seenAt: new Date() });
      updated = true;
    }
  }
  if (updated) await seenDocLeader.save();
}

// Compute badges: show dot ONLY if current > lastSeen
const leaderBadges = {};
for (const [key, val] of Object.entries(leaderCounts)) {
  const last = seenDocLeader.tabs?.get(key)?.count ?? val; // default to current as baseline
  leaderBadges[key] = val > last;
}

const assignedPromptCards = await buildAssignedPromptCards(id);

return res.render('leader_dashboard', {
  layout: 'dashboardlayout',
  title: 'Leader Dashboard',
  csrfToken: req.csrfToken(),
leader: {
  ...userData,
  members: resolvedGroupMembers,
  // existing leader avatar (person)
  profileImage: leaderProfile?.profileImage || '/images/default-avatar.png',
  // NEW: actual group image (circle under the group name)
  groupImage: groupProfile?.groupImage || '/images/defaultgroupavatar.jpg'
},

  leaderGroupMembers: resolvedGroupMembers,
  maxGroupSize: userData.maxGroupSize,
  leaderUnits,
  groupMemberUnits,

  assignedPromptCards,
  leaderAssignmentsOpen,
  leaderAssignmentsCompleted,
  registeredPromptSets: leaderPrompts,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,

  selectedTopics,   // 👈 add this
  topicsEmpty,      // 👈 and this
  topicSuggestions,
  leaderAccount,
  emailPreferenceLevel,
  leaderSelfTaggedUnits,

  mfaStatus,
  leaderCounts,
  leaderBadges,
});




    } catch (err) {
      console.error('Error rendering leader dashboard:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An unexpected error occurred. Please try again later.',
      });
    }
  }, // ← end of renderLeaderDashboard, KEEP THE COMMA

  // --- POST /leader-dashboard/account/email-preferences ---
updateEmailPreferences: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) return res.redirect('/auth/login');

    let level = parseInt(req.body.email_preference_level, 10);
    if (![1, 2, 3].includes(level)) level = 1;

    const result = await Leader.findByIdAndUpdate(
      leaderId,
      { $set: { emailPreferenceLevel: level, emailPreferencesUpdatedAt: new Date() } },
      { new: false }
    );

    console.log('Email preferences updated for leader:', leaderId, '→ level:', level, 'ok:', !!result);

    // Render your success page
    return res.render('partials/dashboardpartials/emailpreferencessuccess', {
      layout: 'dashboardlayout',
      title: 'Email Preferences Updated',
      emailPreferenceLevel: level,
      dashboard: req.baseUrl || '/dashboard/leader'
    });
  } catch (err) {
    console.error('updateEmailPreferences error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'mainlayout',
      title: 'Error',
      errorMessage: 'Could not update email preferences. Please try again.'
    });
  }
},

updateAccountDetails: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) return res.redirect('/auth/login');

    const { name, email, username } = req.body || {};
    const updates = {};

    if (typeof name === 'string' && name.trim()) updates.groupLeaderName = name.trim();
    if (typeof email === 'string' && email.trim()) updates.groupLeaderEmail = email.trim();
    if (typeof username === 'string') updates.username = username.trim();

    const changedCount = Object.keys(updates).length;

    if (changedCount) {
      await Leader.findByIdAndUpdate(leaderId, { $set: updates });
    }

    // Render success page so you can visually confirm it worked
    return res.render('partials/dashboardpartials/accountdetailssuccess', {
      layout: 'dashboardlayout',
      title: 'Account Updated',
      dashboard: req.baseUrl || '/dashboard/leader',
      changedCount,
      // Only echo the values that were actually changed
      name: updates.groupLeaderName,
      email: updates.groupLeaderEmail,
      username: updates.username
    });
  } catch (err) {
    console.error('updateAccountDetails error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'mainlayout',
      title: 'Error',
      errorMessage: 'Could not update account details. Please try again.'
    });
  }
}
}; // ← CLOSES module.exports



