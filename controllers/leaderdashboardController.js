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
const Nugget = require('../models/unit_models/nugget'); // ✅ NEW
const Mission = require('../models/unit_models/mission'); // ✅ NEW
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');
const Organization = require('../models/member_models/organization');



function emailDomain(email = '') {
  const at = String(email).toLowerCase().split('@')[1];
  return at ? at.trim() : '';
}




// Map mission categories to badge image filenames (without extension)
const missionBadgeMap = {
  learning:             'learningbadge',
  research:             'researchbadge',
  business_development: 'bdbadge',
  internal_improvement: 'improvebadge',
  culture_play:         'culturebadge',
  client_experience:    'clientxbadge',
  community:            'communitybadge',
  administrative:       'adminbadge',
  other:                'roguebadge',
};

function getMissionBadgePath(category) {
  const key = category || 'other';
  const filename = missionBadgeMap[key] || missionBadgeMap.other;
  return `/badges/missions/${filename}.png`;
}

function getModelByUnitType(type) {
  switch (type) {
    case 'article':   return Article;
    case 'video':     return Video;
    case 'interview': return Interview;
    case 'exercise':  return Exercise;
    case 'template':  return Template;
    case 'upcoming':  return Upcoming;
    case 'nugget':    return Nugget;
    case 'mission':   return Mission;  // ✅ NEW
    default:          return null;
  }
}


function normalizeUnitType(unit) {
  if (unit.article_title)   return 'article';
  if (unit.video_title)     return 'video';
  if (unit.promptset_title) return 'promptset';
  if (unit.interview_title) return 'interview';
  if (unit.exercise_title)  return 'exercise';
  if (unit.template_title)  return 'template';
  if (unit.mission_title)   return 'mission';
if (unit.title && (unit.discipline || unit.client || unit.region)) return 'nugget';
  return 'unknown';
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
    const tags = await Tag.find({ createdBy: userId }).lean();
    if (!tags.length) return [];

    // include nugget + mission
    const unitMap = {
      article:   [],
      video:     [],
      promptset: [],
      interview: [],
      exercise:  [],
      template:  [],
      upcoming:  [],
      nugget:    [],
      mission:   []   // ✅ NEW
    };

    // key: `${itemId}-${unitType}` → tag doc
    const tagByKey = new Map();

    for (const tag of tags) {
      for (const entry of tag.associatedUnits || []) {
        const itemId = entry.item;
        const unitType = entry.unitType;
        if (!unitMap[unitType]) continue;

        const key = `${itemId.toString()}-${unitType}`;
        unitMap[unitType].push(itemId.toString());

        // last tag wins if multiple tags point to same unit
        tagByKey.set(key, tag);
      }
    }

    const [
      articles,
      videos,
      promptSets,
      interviews,
      exercises,
      templates,
      nuggets,
      missions   // ✅ NEW
    ] = await Promise.all([
      Article.find({ _id: { $in: unitMap.article } }).lean(),
      Video.find({ _id: { $in: unitMap.video } }).lean(),
      PromptSet.find({ _id: { $in: unitMap.promptset } }).lean(),
      Interview.find({ _id: { $in: unitMap.interview } }).lean(),
      Exercise.find({ _id: { $in: unitMap.exercise } }).lean(),
      Template.find({ _id: { $in: unitMap.template } }).lean(),
      Nugget.find({ _id: { $in: unitMap.nugget } }).lean(),
      Mission.find({ _id: { $in: unitMap.mission } }).lean()
    ]);

    const viewPathFor = (type, id) => {
      if (type === 'nugget')  return `/unitviews/nuggets/view/${id}`;
      if (type === 'mission') return `/unitviews/missions/view/${id}`;
      return `/unitviews/${type}s/view/${id}`;
    };

    const tagResult = (units, type, titleField, topicField = 'main_topic') =>
      units.map(unit => {
        const key = `${unit._id.toString()}-${type}`;
        const tag = tagByKey.get(key) || {};
        const assignedCount = Array.isArray(tag.assignedTo) ? tag.assignedTo.length : 0;

return {
  unitType: type,
  title: unit[titleField] || `Untitled ${type}`,
  mainTopic: unit[topicField] || 'No topic',
  _id: unit._id,
  tagId: tag._id ? tag._id.toString() : null,
  assignedCount,
  viewPath: viewPathFor(type, unit._id)
};


      });

    const results = [
      ...tagResult(articles,   'article',   'article_title'),
      ...tagResult(videos,     'video',     'video_title'),
      ...tagResult(promptSets, 'promptset', 'promptset_title'),
      ...tagResult(interviews, 'interview', 'interview_title'),
      ...tagResult(exercises,  'exercise',  'exercise_title'),
      ...tagResult(templates,  'template',  'template_title'),
    ];

    // Nuggets: title is `title`, "topic" uses discipline/client/region
    nuggets.forEach(n => {
      const key = `${n._id.toString()}-nugget`;
      const tag = tagByKey.get(key) || {};
      const assignedCount = Array.isArray(tag.assignedTo) ? tag.assignedTo.length : 0;

      results.push({
        unitType: 'nugget',
        title: n.title || 'Untitled nugget',
        mainTopic: n.discipline || n.client || n.region || 'No classification',
        _id: n._id,
        tagId: tag._id ? tag._id.toString() : null,
        assignedCount,
        viewPath: `/unitviews/nuggets/view/${n._id}`
      });
    });

    // Missions: title is `mission_title`, topic is `main_topic`
// Missions: title is `mission_title`, topic is `main_topic`
missions.forEach(m => {
  const key = `${m._id.toString()}-mission`;
  const tag = tagByKey.get(key) || {};
  const assignedCount = Array.isArray(tag.assignedTo) ? tag.assignedTo.length : 0;

  const category = m.category || 'other';

  // Prefer a mission-specific stored badge path if you have one.
  // Otherwise, fall back to the category default image.
  const badgeImagePath =
    m.badgeImagePath ||
    m.badge_image ||
    m.badgeImage ||
    getMissionBadgePath(category);

  results.push({
    unitType: 'mission',
    title: m.mission_title || 'Untitled mission',
    mainTopic: m.main_topic || 'No topic',
    _id: m._id,
    tagId: tag._id ? tag._id.toString() : null,
    assignedCount,
    viewPath: `/unitviews/missions/view/${m._id}`,

    // ✅ NEW: badge display fields for the partial
    category,
    badge_name: m.badge_name || '',
    badgeImagePath
  });
});


    return results;
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

    for (const { item, unitType } of tag.associatedUnits || []) {
      if (unitType === 'promptset' || unitType === 'prompt') continue;

      const Model = getModelByUnitType(unitType);
      if (!Model) continue;

      const unit = await Model.findById(item).lean();
      if (!unit) continue;

      for (const assignee of tag.assignedTo || []) {
        const member = await GroupMember.findById(assignee.member).select('name').lean();
        if (!member) continue;

const title =
  unit.article_title   ||
  unit.video_title     ||
  unit.interview_title ||
  unit.exercise_title  ||
  unit.template_title  ||
  unit.mission_title   ||   // ✅ NEW: missions
  unit.title           ||   // nuggets (and any other models that use `title`)
  "Untitled";

        const mainTopic = unit.main_topic || unit.discipline || unit.client || unit.region || "No topic";

        const viewPath =
          unitType === 'nugget'
            ? `/unitviews/nuggets/view/${item}`
            : `/unitviews/${unitType}s/view/${item}`;

const category = (unitType === 'mission') ? (unit.category || 'other') : null;

const badgeImagePath =
  (unitType === 'mission')
    ? (unit.badgeImagePath || unit.badge_image || unit.badgeImage || getMissionBadgePath(category))
    : null;

leaderAssignedUnits.push({
  _id: item,
  unitType,
  title,
  mainTopic,
  tagId: tag._id.toString(),
  viewPath,

  // ✅ NEW: badge display fields (missions only)
  category,
  badge_name: (unitType === 'mission') ? (unit.badge_name || '') : '',
  badgeImagePath,

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



const { Types } = require('mongoose');

function fmtDate(d) {
  if (!d) return 'Not set';
  const dd = new Date(d);
  if (Number.isNaN(dd.getTime())) return 'Not set';
  return dd.toLocaleDateString('en-CA', { year: 'numeric', month: 'short', day: '2-digit' });
}

async function buildAssignedPromptCards(leaderId) {
  const leaderObjectId = Types.ObjectId.isValid(leaderId) ? new Types.ObjectId(leaderId) : leaderId;

  const assignments = await AssignPromptSet.find({ groupLeaderId: leaderObjectId }).lean();

  if (!assignments.length) return [];

  const promptSetIds = new Set();
  const memberIds = new Set();
  for (const a of assignments) {
    if (a.promptSetId) promptSetIds.add(a.promptSetId.toString());
    for (const mid of a.assignedMemberIds || []) memberIds.add(mid.toString());
  }

  const [promptSets, members, profiles] = await Promise.all([
    PromptSet.find({ _id: { $in: [...promptSetIds] } }).lean(),
    GroupMember.find({ _id: { $in: [...memberIds] } }).select('name').lean(),
    GroupMemberProfile.find({ groupMemberId: { $in: [...memberIds] } }).select('groupMemberId profileImage').lean()
  ]);

  const psById = new Map(promptSets.map(ps => [ps._id.toString(), ps]));
  const memberById = new Map(members.map(m => [m._id.toString(), m]));
  const profileByMemberId = new Map(profiles.map(p => [p.groupMemberId.toString(), p]));

  const cards = [];
  for (const a of assignments) {
    const ps = psById.get(a.promptSetId?.toString());
    if (!ps) continue;
    const target = a.targetCompletionDate || ps.target_completion_date || null;
    const now = new Date();

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
      if (isCompleted) { status = 'completed'; statusLabel = 'completed'; }
      else if (isOverdue) { status = 'overdue'; statusLabel = 'overdue'; }
      else if (hasStarted) { status = 'inprogress'; statusLabel = 'in progress'; }

      cards.push({
        assignmentId: a._id.toString(),
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

  // sort by real date, not the formatted string
  cards.sort((a, b) => {
    const ad = new Date(a.targetCompletionDate);
    const bd = new Date(b.targetCompletionDate);
    return ad - bd;
  });

  return cards;
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
'Program Management': 'programmanagement',
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
    'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading',
    'When the Workload is Light': 'whentheworkloadislight',
                'The First 10 Days of a Project': 'thefirst10daysofaproject',
            'Managing Scope So It Doesnt Manage You': 'managingscopesoitdoesntmanageyou',
            'Risk Management': 'riskmanagement',
            'Closing a Project Strategically': 'closingaprojectstrategically',
            'Rescuing a Project That Has Gone Off the Rails': 'rescuingaprojectthatsgoneofftherails'

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
'programmanagement': 'single_topic_program',
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
    'tipsandtricksforproposalproofreading': 'single_topic_proofreading',
    'whentheworkloadislight': 'single_topic_workloadlight',
        'thefirst10daysofaproject': 'single_topic_first10days',
    'managingscopesoitdoesntmanageyou': 'single_topic_managingscope',
    'riskmanagement':'single_topic_riskmanagement',
    'closingaprojectstrategically':'single_topic_closing',
    'rescuingaprojectthathasgoneofftherails':'single_topic_rescuing'

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

    // ✅ org fields
    'organization',
    'organizationOptOut',
    'organizationName',
    'isAdmin',




    'topics',
    'members',

    // 👇 MFA
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

  // ------------------------------------------------------------
// ✅ Suggest an existing organization by email domain
// Only when leader has no org and has not opted out
// ------------------------------------------------------------
let suggestedOrg = null;

const canSuggestOrg =
  !userData?.organization &&
  userData?.organizationOptOut !== true &&
  !!userData?.groupLeaderEmail;

if (canSuggestOrg) {
  const domain = emailDomain(userData.groupLeaderEmail);
  if (domain) {
    suggestedOrg = await Organization.findOne({
      isActive: true,
      domains: domain
    })
      .select('name slug industry')
      .lean();
  }
}

  
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


// ------------------------------------------------------------
// ✅ Organization: "groups in my organization"
// ------------------------------------------------------------
let orgGroups = [];

const hasOrg =
  !!userData?.organization &&
  userData?.organizationOptOut !== true;

if (hasOrg) {
  // other leaders in same org (each Leader is a group)
  const otherLeaders = await Leader.find({
    organization: userData.organization,
    organizationOptOut: { $ne: true },
    isActive: true,
    _id: { $ne: userData._id }
  })
    .select('groupName groupLeaderName members groupSize')
    .lean();

  if (otherLeaders.length) {
    // attach group images from GroupProfile
    const ids = otherLeaders.map(l => l._id);
    const profiles = await GroupProfile.find({ groupId: { $in: ids } })
      .select('groupId groupImage')
      .lean();

    const imgByGroupId = new Map(
      profiles.map(p => [p.groupId.toString(), p.groupImage])
    );

orgGroups = otherLeaders.map(l => ({
  _id: l._id,
  groupName: l.groupName,
  groupLeaderName: l.groupLeaderName,
  groupImage: imgByGroupId.get(l._id.toString()) || '/images/default-group.png',
  memberCount: Array.isArray(l.members) ? l.members.length : (l.groupSize || 0)
}));
  }
}

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
  groupUpcomings,  // uses createdBy
  groupNuggets     // ✅ NEW
] = await Promise.all([
  Article.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Video.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  PromptSet.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Interview.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Exercise.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Template.find({ 'author.id': { $in: leaderGroupMemberIds } }).lean(),
  Upcoming.find({ createdBy: { $in: leaderGroupMemberIds } }).lean(),
  Nugget.find({ createdBy: { $in: leaderGroupMemberIds } }).lean()   // ✅ NEW
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

const gmNuggetRows = await Promise.all(
  (groupNuggets || []).map(async (n) => {
    const author = await resolveAuthorById(n.createdBy);
    return {
      author: author?.name || 'Group Member',
      unitType: 'nugget',
      title: n.title,
      status: '—', // nuggets have no status; you can change to 'active' if you prefer
      mainTopic: n.discipline || n.client || n.region || 'No classification',
      _id: n._id
    };
  })
);

// Keep existing upcoming append
groupMemberUnits = [...groupMemberUnits, ...gmUpcomingRows, ...gmNuggetRows];

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

// ✅ Split self-tagged units into missions vs non-missions
const leaderSelfTaggedMissions = leaderSelfTaggedUnits.filter(u => u.unitType === 'mission');
const leaderSelfTaggedNonMissionUnits = leaderSelfTaggedUnits.filter(u => u.unitType !== 'mission');


const [
  leaderArticles,
  leaderVideos,
  leaderPromptSets,
  leaderInterviews,
  leaderExercises,
  leaderTemplates,
    leaderMissions          // ← ADD THIS
] = await Promise.all([
  Article.find({ 'author.id': id }),
  Video.find({ 'author.id': id }),
  PromptSet.find({ 'author.id': id }),
  Interview.find({ 'author.id': id }),
  Exercise.find({ 'author.id': id }),
  Template.find({ 'author.id': id }),
    Mission.find({ created_by: id })  // ← FETCH LEADER MISSIONS
]);

const [leaderUpcomings, leaderNuggets] = await Promise.all([
  Upcoming.find({ createdBy: id }).lean(),
  Nugget.find({ createdBy: id }).lean()
]);

let leaderUnits = await Promise.all(
  [...leaderArticles, ...leaderVideos, ...leaderPromptSets, ...leaderInterviews, ...leaderExercises, ...leaderTemplates, ...leaderUpcomings, ...leaderNuggets, ...leaderMissions].map(async (unit) => {
    const author = await resolveAuthorById(pickAuthorId(unit));
return {
  unitType: normalizeUnitType(unit),
  title:
    unit.mission_title ||
    unit.article_title ||
    unit.video_title ||
    unit.promptset_title ||
    unit.interview_title ||
    unit.exercise_title ||
    unit.template_title ||
    unit.title ||
    "Untitled Unit",
  status: unit.status || "Unknown",
  mainTopic: unit.main_topic || unit.discipline || unit.client || unit.region || "No topic",
  _id: unit._id,
  author: author.name
};
  })
);


// Now build rows to append
const leaderUpcomingRows = (leaderUpcomings || []).map((u) => ({
  unitType: 'upcoming',
  plannedType: u.unit_type, // e.g., 'video'
  title: u.title,
  status: u.status || 'in production',
  mainTopic: u.main_topic || 'No topic',
  _id: u._id,
  projectedRelease: u.projected_release_at
}));

const leaderNuggetRows = (leaderNuggets || []).map((n) => ({
  unitType: 'nugget',
  title: n.title,
  status: '—', // nuggets have no status
  mainTopic: n.discipline || n.client || n.region || 'No classification',
  _id: n._id
}));

// Append once
leaderUnits = [...leaderUnits, ...leaderNuggetRows, ...leaderUpcomingRows];



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
  completedAt: record.completedAt
    ? new Date(record.completedAt).toDateString()
    : 'Unknown Date',
  badge: record.earnedBadge // object with { image, name } if present
}));

// ---------- GROUP COMPLETED PROMPT SETS (for group badges) ----------

// map memberId → name using the resolvedGroupMembers we already built
const memberNameById = new Map(
  (resolvedGroupMembers || []).map(m => [m._id.toString(), m.name])
);

// all completions for any member in this leader's group
const groupCompletedRecords = await PromptSetCompletion
  .find({ memberId: { $in: leaderGroupMemberIds } })
  .populate('promptSetId')
  .lean();

const groupCompletedPromptSets = groupCompletedRecords.map(record => ({
  promptSetTitle: record.promptSetId?.promptset_title || 'Unknown Title',
  frequency: record.promptSetId?.suggested_frequency,
  mainTopic: record.promptSetId?.main_topic || 'No Topic',
  completedAt: record.completedAt
    ? new Date(record.completedAt).toDateString()
    : 'Unknown Date',
  badge: record.earnedBadge,
  memberName: memberNameById.get(record.memberId?.toString()) || 'Group Member'
}));



// Map the completion records to a formatted array
const { leaderAssignedUnits, leaderAssignmentsOpen, leaderAssignmentsCompleted } = await buildLeaderAssignedUnits(id);
// --- Membership tab: derive view flags & user fields for template ---

// ✅ helper to flatten assignedTo for the template
const mapAssigned = (u) => ({
  ...u,
  assignedToName: u.assignedTo?.name || '',
  assignedToId: u.assignedTo?._id || '',
  assignedInstructions: u.assignedTo?.instructions || '',
  assignedCompletedAtFormatted: u.assignedTo?.completedAt ? fmtDate(u.assignedTo.completedAt) : ''
});

// ✅ First, separate nuggets vs non-nuggets
const leaderAssignedNonNuggetUnitsRaw = leaderAssignedUnits.filter(u => u.unitType !== 'nugget');
const leaderAssignedNuggetsRaw      = leaderAssignedUnits.filter(u => u.unitType === 'nugget');

// ✅ Then split missions out of the non-nugget set
const leaderAssignedMissionsRaw        = leaderAssignedNonNuggetUnitsRaw.filter(u => u.unitType === 'mission');
const leaderAssignedNonMissionUnitsRaw = leaderAssignedNonNuggetUnitsRaw.filter(u => u.unitType !== 'mission');

// ✅ Flatten for the template
const leaderAssignedNonNuggetUnits  = leaderAssignedNonNuggetUnitsRaw.map(mapAssigned);   // existing blended non-nuggets
const leaderAssignedNuggets         = leaderAssignedNuggetsRaw.map(mapAssigned);          // existing assigned nuggets
const leaderAssignedMissions        = leaderAssignedMissionsRaw.map(mapAssigned);         // NEW: missions only
const leaderAssignedNonMissionUnits = leaderAssignedNonMissionUnitsRaw.map(mapAssigned);  // NEW: non-mission, non-nugget


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
console.log('assignedPromptCards count:', assignedPromptCards.length);
if (assignedPromptCards[0]) console.log('assignedPromptCards[0] sample:', assignedPromptCards[0]);







return res.render('leader_dashboard', {
  layout: 'dashboardlayout',
  title: 'Leader Dashboard',
csrfToken: req.csrfToken ? req.csrfToken() : null,
leader: {
  ...userData,
  hasOrg,
  organizationName: userData.organizationName || '',
  members: resolvedGroupMembers,
  profileImage: leaderProfile?.profileImage || '/images/default-avatar.png',
  groupImage: groupProfile?.groupImage || '/images/defaultgroupavatar.jpg'
},
suggestedOrg,
orgGroups,

  leaderGroupMembers: resolvedGroupMembers,
  maxGroupSize: userData.maxGroupSize,
  // Library + group units
  leaderUnits,
  groupMemberUnits,

  // Assignment data
  leaderAssignedUnits,         // raw assigned units, if you still need them
  leaderAssignmentsOpen,
  leaderAssignmentsCompleted,
  assignedPromptCards,

  // Prompt set data
  registeredPromptSets: leaderPrompts,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,
    groupCompletedPromptSets,

  // Topics / suggestions
  selectedTopics,
  topicsEmpty,
  topicSuggestions,

  // Account / email prefs
  leaderAccount,
  emailPreferenceLevel,

  // ✅ TAGGED / ASSIGNED UNITS (new + existing)
  leaderSelfTaggedUnits,              // blended, all self-tagged (for backwards compat)
  leaderSelfTaggedNonMissionUnits,    // NEW: self-tagged non-mission units
  leaderSelfTaggedMissions,           // NEW: self-tagged missions

  leaderAssignedNonNuggetUnits,       // existing blended non-nuggets
  leaderAssignedNonMissionUnits,      // NEW: assigned non-mission, non-nugget
  leaderAssignedMissions,             // NEW: assigned missions
  leaderAssignedNuggets,              // existing assigned nuggets

  // MFA + tab badges
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

  // ------------------------------------------------------------
// ✅ GET /leader/organization/success
// Renders /views/organization-success.hbs (root views folder)
// ------------------------------------------------------------
organizationSuccess: (req, res) => {
  try {
    // Optional: show the org name once, then clear it
    const organizationName = req.session?.organizationJustCreatedName || null;

    // TODO: set this to your actual leader dashboard route
const dashboardUrl = '/dashboard/leader';

    // Clear the one-time name so refresh doesn't keep showing it
    if (req.session?.organizationJustCreatedName) {
      delete req.session.organizationJustCreatedName;
    }

    return res.render('organization-success', {
      layout: 'dashboardlayout',
      title: 'Organization Created',
      organizationName,
      dashboardUrl
    });
  } catch (err) {
    console.error('organizationSuccess render error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'mainlayout',
      title: 'Error',
      errorMessage: 'Could not load the organization success page. Please try again.'
    });
  }
},

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

searchOrganizations: async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) {
      return res.json({ organizations: [] });
    }

    // Escape regex specials
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rx = new RegExp(escaped, 'i');

    const organizations = await Organization.find({
      isActive: true,
      $or: [{ name: rx }, { slug: rx }]
    })
      .select('_id name slug')
      .limit(8)
      .lean();

    return res.json({ organizations });
  } catch (err) {
    console.error('searchOrganizations error:', err);
    return res.status(500).json({ organizations: [] });
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
},



// controllers/leaderController.js (or leaderdashboardController — your call)
joinOrganizationByDomain: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) return res.redirect('/auth/login');

    const leader = await Leader.findById(leaderId);
    if (!leader) return res.status(404).render('member_form_views/error', { /* ... */ });

    // already joined?
    if (leader.organization && leader.organizationOptOut !== true) {
      return res.redirect('/dashboard/leader');
    }

    const orgId = req.body.orgId;
    const org = await Organization.findById(orgId).lean();
    if (!org || !org.isActive) {
      return res.status(400).render('member_form_views/error', { /* ... */ });
    }

    const domain = emailDomain(leader.groupLeaderEmail);
    const ok = domain && Array.isArray(org.domains) && org.domains.includes(domain);

    if (!ok) {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Allowed',
        errorMessage: 'Your email domain does not match this organization.'
      });
    }

    leader.organization = org._id;
    leader.organizationName = org.name;
    leader.organizationOptOut = false;
    await leader.save();

    await GroupProfile.updateOne(
      { groupId: leader._id },
      { $set: { organization: org._id } }
    );

    req.session.organizationJustCreatedName = org.name; // reuse your success page text
    return res.redirect('/dashboard/leader/organization/success');
  } catch (err) {
    console.error('joinOrganizationByDomain error:', err);
    return res.status(500).render('member_form_views/error', { /* ... */ });
  }
},

requestJoinOrganization: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) return res.redirect('/auth/login');

    const { organizationId, orgSlugOrName } = req.body || {};

    let org = null;

    // ✅ Preferred: ID from autocomplete selection
    if (organizationId && mongoose.Types.ObjectId.isValid(organizationId)) {
      org = await Organization.findOne({ _id: organizationId, isActive: true })
        .select('_id name')
        .lean();
    }

    // Fallback: typed name/slug (your original behavior)
    if (!org) {
      const q = String(orgSlugOrName || '').trim().toLowerCase();
      if (!q) return res.redirect('/dashboard/leader');

      org = await Organization.findOne({
        isActive: true,
        $or: [
          { slug: q },
          { name: new RegExp(`^${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
        ]
      }).select('_id name').lean();
    }

    if (!org) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'No organization found by that name.'
      });
    }

    await OrganizationJoinRequest.findOneAndUpdate(
      { organization: org._id, leader: leaderId },
      { $setOnInsert: { organization: org._id, leader: leaderId, status: 'pending' } },
      { upsert: true, new: true }
    );

    return res.redirect('/dashboard/leader');
  } catch (err) {
    console.error('requestJoinOrganization error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'Could not send join request. Please try again.'
    });
  }
}



}; // ← CLOSES module.exports



