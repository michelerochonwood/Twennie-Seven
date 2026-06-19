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
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const fs = require('fs');
const path = require('path');
const MemberProfile = require('../models/profile_models/member_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const TopicSuggestion = require('../models/topic/topic_suggestion');
const Upcoming = require('../models/unit_models/upcoming');
const DashboardSeen = require('../models/dashboard_seen');
const Nugget = require('../models/unit_models/nugget'); // ✅ NEW
const GroupProfile = require('../models/profile_models/group_profile'); // ✅ NEW
const Mission = require('../models/unit_models/mission'); // ✅ NEW
const Note = require('../models/notes/notes');
const ArchivedUnit = require('../models/archivedUnit');




//resolveAuthorById is necessary for showing library units in the library unit table. We have no author property in the unit models, so the resolve function allows the library units to show the author. Don't delete any code in the library units meant to resolve the author by id.

async function resolveAuthorById(authorId) {
    try {
        // Leader profile
        let profile = await LeaderProfile.findOne({ leaderId: authorId }).select('profileImage name');
        if (profile) {
            return {
                name: profile.name || 'Leader',
                image: profile.profileImage || '/images/default-avatar.png'
            };
        }

        // Group Member profile
        profile = await GroupMemberProfile.findOne({ groupMemberId: authorId }).select('profileImage name');

        if (profile) {
            return {
                name: profile.name || 'Group Member',
                image: profile.profileImage || '/images/default-avatar.png'
            };
        }

        // Individual Member profile
        profile = await MemberProfile.findOne({ memberId: authorId }).select('profileImage name');
        if (profile) {
            return {
                name: profile.name || 'Member',
                image: profile.profileImage || '/images/default-avatar.png'
            };
        }
    } catch (error) {
        console.error('Error resolving author profile:', error);
    }

    return {
        name: 'Unknown Author',
        image: '/images/default-avatar.png'
    };
}


const topicMappings = {
  'AI in Adult Learning': 'aiinadultlearning',
  'AI in Consulting': 'aiinconsulting',
  'AI in Project Management': 'aiinprojectmanagement',
  'Business Development in Technical Services': 'businessdevelopmentintechnicalservices',
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
  'Leading Groups and Creating Content on Twennie': 'leadinggroupsontwennie',
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
  'Proposal Pricing Strategies': 'proposalpricingstrategies',
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
  'businessdevelopmentintechnicalservices': 'single_topic_bd',
  'candidcommunication': 'single_topic_candid',
  'careerdevelopmentintechnicalservices': 'single_topic_careerdev',
  'clientexperience': 'single_topic_clientex',
  'clientfeedbacksoftware': 'single_topic_clientfeedback',
  'clientinteractions': 'single_topic_clientinteractions',
  'closingaprojectstrategically': 'single_topic_closing',
  'competitorintelligencealicensetodifferentiate': 'single_topic_differentiate',
  'conductingcolorreviews': 'single_topic_colorreviews',
  'conductingmarketresearch': 'single_topic_research',
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
  'leadinggroupsandcreatingcontentontwennie': 'single_topic_leadinggroupsontwennie',
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
  'proposalpricingstrategies': 'single_topic_pricing',
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


async function fetchTaggedUnits(userId) {
  try {
    // Tags I created (self-tags) OR tags assigned to me
    const tags = await Tag.find({
      $or: [{ createdBy: userId }, { 'assignedTo.member': userId }]
    }).lean();

    if (!tags.length) return [];

    // include upcoming + nugget + mission
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

    const tagLookup = new Map(); // `${itemId}-${unitType}` → tag

    for (const tag of tags) {
      for (const { item, unitType } of tag.associatedUnits || []) {
        if (unitMap[unitType]) {
          const key = `${item.toString()}-${unitType}`;
          unitMap[unitType].push(item.toString());
          tagLookup.set(key, tag);
        }
      }
    }

    const [
      articles,
      videos,
      promptSets,
      interviews,
      exercises,
      templates,
      upcomings,
      nuggets,
      missions   // ✅ NEW
    ] = await Promise.all([
      Article.find({ _id: { $in: unitMap.article } }),
      Video.find({ _id: { $in: unitMap.video } }),
      PromptSet.find({ _id: { $in: unitMap.promptset } }),
      Interview.find({ _id: { $in: unitMap.interview } }),
      Exercise.find({ _id: { $in: unitMap.exercise } }),
      Template.find({ _id: { $in: unitMap.template } }),
      Upcoming.find({ _id: { $in: unitMap.upcoming } }),
      Nugget.find({ _id: { $in: unitMap.nugget } }),
      Mission.find({ _id: { $in: unitMap.mission } })
    ]);

    const viewPathFor = (type, id) =>
      type === 'nugget'
        ? `/unitviews/nuggets/view/${id}`
        : type === 'mission'
          ? `/unitviews/missions/view/${id}`
          : `/unitviews/${type}s/view/${id}`; // generic fallback

    const tagResult = (units, type, titleField, topicField = 'main_topic') =>
      units.map(unit => {
        const key = `${unit._id.toString()}-${type}`;
        const tag = tagLookup.get(key);
        const assignment = (tag?.assignedTo || []).find(a => String(a.member) === String(userId));

const completionInfo = {};

        return {
          unitType: type,
          title: unit[titleField] || `Untitled ${type}`,
          mainTopic: unit[topicField] || 'No topic',
          _id: unit._id,
          tagId: tag?._id?.toString() || null,
          tagIdCreator: tag?.createdBy?.toString() || null,
          instructions: assignment?.instructions || '',
          completedAt: assignment?.completedAt || completionInfo.completedAt || null,
          viewPath: viewPathFor(type, unit._id),

          // ✅ NEW: for completed prompt set cards
          earnedBadge: completionInfo.earnedBadge || null
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

    // upcoming (title field is `title`)
    upcomings.forEach(u => {
      const key = `${u._id.toString()}-upcoming`;
      const tag = tagLookup.get(key);
      const assignment = (tag?.assignedTo || []).find(a => String(a.member) === String(userId));
      results.push({
        unitType: 'upcoming',
        title: u.title || 'Untitled upcoming',
        mainTopic: u.main_topic || 'No topic',
        _id: u._id,
        tagId: tag?._id?.toString() || null,
        tagIdCreator: tag?.createdBy?.toString() || null,
        instructions: assignment?.instructions || '',
        completedAt: assignment?.completedAt || null,
        viewPath: viewPathFor('upcoming', u._id)
      });
    });

    // nugget (title = `title`, topic fallback: discipline/client/region)
    nuggets.forEach(n => {
      const key = `${n._id.toString()}-nugget`;
      const tag = tagLookup.get(key);
      const assignment = (tag?.assignedTo || []).find(a => String(a.member) === String(userId));
      results.push({
        unitType: 'nugget',
        title: n.title || 'Untitled nugget',
        mainTopic: n.discipline || n.client || n.region || 'No classification',
        _id: n._id,
        tagId: tag?._id?.toString() || null,
        tagIdCreator: tag?.createdBy?.toString() || null,
        instructions: assignment?.instructions || '',
        completedAt: assignment?.completedAt || null,
        viewPath: viewPathFor('nugget', n._id)
      });
    });

    // mission (title = `mission_title`, topic = `main_topic`)
// mission (title = `mission_title`, topic = `main_topic`) + ✅ badge fields
missions.forEach(m => {
  const key = `${m._id.toString()}-mission`;
  const tag = tagLookup.get(key);
  const assignment = (tag?.assignedTo || []).find(a => String(a.member) === String(userId));

  const category = m.category || 'other';

  // Prefer a mission-specific stored badge path if you ever add it later; otherwise category default
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
    tagId: tag?._id?.toString() || null,
    tagIdCreator: tag?.createdBy?.toString() || null,
    instructions: assignment?.instructions || '',
    completedAt: assignment?.completedAt || null,
    viewPath: viewPathFor('mission', m._id),

    // ✅ NEW: for mission cards
    category,
    badge_name: m.badge_name || '',
    badgeImagePath
  });
});
    return results;
  } catch (error) {
    console.error('❌ Error fetching tagged units for group member:', error);
    return [];
  }
}






//everything in this function, getPromptSchedule, is necessary - rewrite it exactly as it is without deleting anything

async function getPromptSchedule(memberId, promptSetId) {
    let targetDate = null;

    const registration = await PromptSetRegistration.findOne({ memberId, promptSetId });
    if (registration) {
        targetDate = registration.targetCompletionDate;
} else {
  const memberOid = new (require('mongoose').Types.ObjectId)(memberId);
  const assignment = await AssignPromptSet.findOne({
    promptSetId,
    assignedMemberIds: memberOid
  });
  if (assignment) {
    targetDate = assignment.targetCompletionDate;
  }
}

    if (!targetDate) {
        console.warn(`No target date found for member ${memberId} and promptSetId ${promptSetId}`);
        return null;
    }

    // Calculate remaining days from today until the target date.
    const today = new Date();
    targetDate = new Date(targetDate);
    const remainingDays = Math.max(0, Math.ceil((targetDate - today) / (1000 * 60 * 60 * 24)));

    // Use a constant so that it's clear this is the total number of prompts.
    const totalPrompts = 21; // For Prompt0 plus Prompts 1–20

    const progress = await PromptSetProgress.findOne({ memberId, promptSetId });
    const remainingPrompts = progress ? totalPrompts - progress.completedPrompts.length : totalPrompts;

    const spread = remainingPrompts > 0 ? Math.floor(remainingDays / remainingPrompts) : 0;

    return {
        targetCompletionDate: targetDate.toDateString(),
        recommendedCompletionDate: new Date(today.getTime() + spread * 24 * 60 * 60 * 1000).toDateString(),
        remainingDays,
        remainingPrompts,
        spread
    };
}



// Function to get subtopics from topics.json
function getSubtopics(topicTitle) {
    const topicsFilePath = path.join(__dirname, '../public/data/topics.json');
    
    if (!fs.existsSync(topicsFilePath)) {
        console.error('topics.json file is missing.');
        return [];
    }

    const topicsData = JSON.parse(fs.readFileSync(topicsFilePath, 'utf8'));
    const topic = topicsData.topics.find(t => t.title === topicTitle);
    
    return topic ? topic.subtopics : []; // Return an empty array if no subtopics found
}


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


// ---- SAFETY HELPERS (dashboard tabs + csrf) ----
function safeCsrfToken(req) {
  try {
    return (typeof req.csrfToken === 'function') ? req.csrfToken() : null;
  } catch (e) {
    console.warn('[groupmemberdashboard] csrfToken unavailable:', e.message || e);
    return null;
  }
}

// Ensure DashboardSeen.tabs always supports get/set/has (Map-like)
// Works even if older documents stored tabs as plain objects.
function ensureTabsMap(seenDoc) {
  if (!seenDoc) return;

  const t = seenDoc.tabs;

  // Already Map-like (Mongoose Map or native Map)
  if (t && typeof t.get === 'function' && typeof t.set === 'function') return;

  // Convert plain object -> Map
  const raw = (t && typeof t === 'object') ? t : {};
  const m = new Map();
  for (const [k, v] of Object.entries(raw)) {
    m.set(k, v);
  }
  seenDoc.tabs = m;
}


module.exports = {
    renderGroupMemberDashboard: async (req, res) => {

        try {
            const { id } = req.session.user;


let currentPromptSets = [];

let completedPromptSets = [];



            console.log("Fetching dashboard for user:", id);



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

// ✅ NEW: completed prompt set archive tracking
const archivedCompletedPromptSetIds = new Set(
  archivedUnits
    .filter(a =>
      a.unitType === 'promptset' &&
      String(a.assignedToMember || '') === String(id)
    )
    .map(a => String(a.unitId))
);

function isArchivedCompletedPromptSet(promptSetId) {
  if (!promptSetId) return false;
  return archivedCompletedPromptSetIds.has(String(promptSetId));
}

// existing tag-based archive logic
function isArchivedDashboardItem(tagId, unitId, assignedToId = null) {
  if (!tagId || !unitId) return false;

  if (assignedToId) {
    return archivedKeySet.has(`${String(tagId)}-${String(unitId)}-${String(assignedToId)}`);
  }

  return (
    archivedKeySet.has(`${String(tagId)}-${String(unitId)}-self`) ||
    archivedKeySet.has(`${String(tagId)}-${String(unitId)}-${String(id)}`)
  );
}

            //members of a group are meant to show in the group member dashboard as cards - it is important that none of this changed because the group members are located based on the leader of the group - if you are rewriting anything in this renderdashboard, make sure to rewrite it exactly as you see it here. 
    
const userData = await GroupMember.findById(id)
  .select('name email username profileImage professionalTitle organization groupId leader emailPreferenceLevel termsAccepted mfa.enabled mfa.method mfa.recoveryCodes mfa.updatedAt')
  .lean();

if (!userData) {
  console.error(`Group Member with ID ${id} not found.`);
  return res.status(404).render('error', {
    title: 'Error',
    errorMessage: `Group Member with ID ${id} not found.`
  });
}

// ✅ Load the leader (this is the "group")
const leaderId = userData.groupId || userData.leader; // ✅ prefer new field, fallback old

const leaderDoc = await Leader.findById(leaderId)
  .select('groupName groupLeaderName groupSize topics members organization organizationName organizationOptOut')
  .populate({ path: 'members', model: 'GroupMember', select: 'name professionalTitle' })
  .lean();

  console.log('[GM DASH] leaderId resolved to:', leaderId ? leaderId.toString() : leaderId);


if (!leaderDoc) {
  return res.status(404).render('error', {
    title: 'Error',
    errorMessage: 'Leader/group not found for this group member.'
  });
}


// Guard: groupId or groupId.topics may be missing...
const groupProfileDoc = await GroupProfile
  .findOne({ groupId: leaderDoc._id })
  .select('groupImage')
  .lean();

// We will build a plain object for groupMember to guarantee the extra field is present
const groupMemberObj = { ...userData };
// Keep group image on the separate `group` object (recommended)


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

        
console.log("🔍 Fetched user data:", JSON.stringify(userData, null, 2));


/* ---------- SAFE TOPICS (based on leader's group) ---------- */
function gmBuildTopicObj(title) {
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

// Guard: groupId or groupId.topics may be missing for new setups
const leaderTopics =
  (leaderDoc && typeof leaderDoc.topics === 'object')
    ? leaderDoc.topics
    : {};

const selectedTopics = {
  topic1: gmBuildTopicObj(leaderTopics.topic1 || null),
  topic2: gmBuildTopicObj(leaderTopics.topic2 || null),
  topic3: gmBuildTopicObj(leaderTopics.topic3 || null)
};

console.log("Selected Topics with View Names:", selectedTopics);

/* ---------- GROUP MEMBERS (safe) ---------- */
console.log("Fetched user data (object):", userData);
console.log(
  "Group members before processing:",
  JSON.stringify(leaderDoc.members || [], null, 2)
);

// ✅ Resolve each member's avatar from GroupMemberProfile
// ✅ Resolve avatars from GroupMemberProfile to ensure pictures show up
let groupMembers = [];
if (Array.isArray(leaderDoc?.members) && leaderDoc.members.length > 0) {
  groupMembers = await Promise.all(
    leaderDoc.members.map(async (m) => {
      const prof = await GroupMemberProfile
        .findOne({ groupMemberId: m._id })
        .select('profileImage')
        .lean();

      return {
        _id: m._id,
        name: m.name,
        professionalTitle: m.professionalTitle || '',
        profileImage: prof?.profileImage || '/images/default-avatar.png'
      };
    })
  );
}




/* ---------- PROMPTSET REGISTRATIONS / ASSIGNMENTS ---------- */
const memberRegistrations = await PromptSetRegistration
  .find({ memberId: id })
  .populate('promptSetId');

const memberOid = new (require('mongoose').Types.ObjectId)(id);

const assignedPromptSets = await AssignPromptSet
  .find({ assignedMemberIds: memberOid })
  .populate('promptSetId');

console.log(`Total assigned prompt sets for member ${id}: ${assignedPromptSets.length}`);
console.log(`Total prompt sets found for member ${id}: ${memberRegistrations.length}`);




    
            let groupmemberPrompts = [];
            let promptSchedules = [];
    
            await Promise.all(
                [...memberRegistrations, ...assignedPromptSets].map(async (registration) => {
                    const promptSet = await PromptSet.findById(registration.promptSetId);
                    if (!promptSet) return;
            
                    // Check if a completion record exists
                    const completion = await PromptSetCompletion.findOne({ memberId: id, promptSetId: registration.promptSetId });
                    if (completion) {
                        completedPromptSets.push({
                            promptSetTitle: promptSet.promptset_title,
                            frequency: registration.frequency,
                            mainTopic: promptSet.main_topic,
                            completedAt: completion.completedAt ? new Date(completion.completedAt).toDateString() : "Unknown Date",
                            badge: promptSet.badge
                        });
                    } else {
                        // Process progress for current prompt sets
                        const progress = await PromptSetProgress.findOne({ memberId: id, promptSetId: registration.promptSetId });
                        const currentPromptIndex = progress?.currentPromptIndex ?? 0;
            
                        console.log(`Progress for promptSetId ${registration.promptSetId._id}: ${currentPromptIndex}`);
            
                        const headlineKey = `prompt_headline${currentPromptIndex}`;
                        const promptKey = `Prompt${currentPromptIndex}`;
                        // ✅ Fetch the leader first, before using it
                        const leader = leaderDoc;


                        if (!leader) {
                            console.error("❌ ERROR: Leader not found for leaderDoc:", leaderDoc?._id);
                        } else {
                            console.log("✅ Leader Found:", leader.groupLeaderName);
                        }
                        groupmemberPrompts.push({
                            registrationId: registration._id,
                            promptSetId: registration.promptSetId._id.toString(),
                            promptSetTitle: promptSet.promptset_title,
                            frequency: registration.frequency,
                            mainTopic: promptSet.main_topic,
                            purpose: promptSet.purpose,
                            promptHeadline: promptSet[headlineKey] || "No headline found",
                            promptText: promptSet[promptKey] || "No prompt text found",
                            promptIndex: currentPromptIndex,
                            leaderNotes: registration.leaderNotes || null, // Ensure leaderNotes is included,
                            leaderName: leader ? leader.groupLeaderName : "Group Leader"
                        });
            
                        promptSchedules.push(await getPromptSchedule(id, registration.promptSetId));
                    }
                })
            );
            
            
    
const allTaggedUnits = await fetchTaggedUnits(id);

const taggedPromptSetById = new Map(
  (allTaggedUnits || [])
    .filter(u => u.unitType === 'promptset')
    .map(u => [String(u._id), u])
);

// ✅ 1) Self-tagged (all unit types, including upcoming + nuggets)
const groupMemberSelfTaggedRaw = allTaggedUnits
  .filter(u => u.tagIdCreator === id.toString());

const groupMemberSelfTaggedUnitIds = groupMemberSelfTaggedRaw.map(u => u._id);

const groupMemberNotes = groupMemberSelfTaggedUnitIds.length
  ? await Note.find({
      memberID: id,
      unitID: { $in: groupMemberSelfTaggedUnitIds }
    })
      .select('unitID updatedAt createdAt')
      .lean()
  : [];

const groupMemberNoteByUnitId = new Map(
  groupMemberNotes.map(n => [
    n.unitID.toString(),
    n.updatedAt || n.createdAt || null
  ])
);

const groupMemberSelfTaggedUnits = groupMemberSelfTaggedRaw
  .filter(u => !isArchivedDashboardItem(u.tagId, u._id, id))
  .map(u => {
  const completedAt = groupMemberNoteByUnitId.get(u._id.toString()) || null;

  return {
    ...u,
    completedAtFormatted: completedAt
      ? new Date(completedAt).toLocaleDateString('en-CA', {
          year: 'numeric',
          month: 'short',
          day: '2-digit'
        })
      : ''
  };
});

// ✅ 2) Leader-assigned (all unit types, including upcoming + nuggets)
const assignedRaw = allTaggedUnits
  .filter(u => u.tagIdCreator && u.tagIdCreator !== id.toString());

// (Optional) fetch leader names for the “assigned by” line
const creatorIds = [...new Set(assignedRaw.map(u => u.tagIdCreator).filter(Boolean))];
const leaders = creatorIds.length
  ? await Leader.find({ _id: { $in: creatorIds } }).select('_id groupLeaderName').lean()
  : [];
const leaderNameById = new Map(leaders.map(l => [l._id.toString(), l.groupLeaderName || 'Group Leader']));

// Flatten the assigned array with friendly fields
const groupMemberAssignedUnits = assignedRaw
  .filter(u => !isArchivedDashboardItem(u.tagId, u._id, id))
  .map(u => ({
    ...u,
    leaderName: leaderNameById.get(u.tagIdCreator) || 'Group Leader',
    assignedToId: id,
    assignedInstructions: u.instructions || '',
    assignedCompletedAtFormatted: u.completedAt
      ? new Date(u.completedAt).toLocaleDateString('en-CA', {
          year: 'numeric',
          month: 'short',
          day: '2-digit'
        })
      : ''
  }));


// ✅ Split self-tagged / assigned into nuggets & missions
const groupMemberTaggedNuggets = groupMemberSelfTaggedUnits.filter(u => u.unitType === 'nugget');
const groupMemberTaggedMissions = groupMemberSelfTaggedUnits.filter(u => u.unitType === 'mission');

const groupMemberAssignedNuggets = groupMemberAssignedUnits.filter(u => u.unitType === 'nugget');
const groupMemberAssignedMissions = groupMemberAssignedUnits.filter(u => u.unitType === 'mission');

// ✅ Build missionBadges from completed assigned missions (uses Tag.assignedTo.completedAt)
const completedAssignedMissionIds = (groupMemberAssignedMissions || [])
  .filter(m => !!m.completedAt) // completedAt comes from Tag.assignedTo.completedAt
  .map(m => m._id?.toString())
  .filter(Boolean);

// Fetch mission docs for those completions so we can show badge name + image
const completedMissionDocs = completedAssignedMissionIds.length
  ? await Mission.find({ _id: { $in: completedAssignedMissionIds } })
      .select('mission_title badge_name category badgeImagePath badge_image badgeImage')
      .lean()
  : [];

const missionBadges = completedMissionDocs.map(doc => {
  const category = doc.category || 'other';
  const badgePath =
    doc.badgeImagePath ||
    doc.badge_image ||
    doc.badgeImage ||
    getMissionBadgePath(category);

  return {
    missionId: doc._id.toString(),
    title: doc.mission_title || 'Untitled mission',
    badgePath,
    badgeName: doc.badge_name || 'Mission Badge',

    // We want the completion date from the tag assignment record.
    // Find it by matching mission id back to the assigned missions array.
    completed_at: (groupMemberAssignedMissions.find(m => String(m._id) === String(doc._id))?.completedAt) || null
  };
});


// ✅ NEW: non-mission non-nugget buckets for the tagged tab partial
const groupMemberSelfTaggedNonMissionUnits =
  groupMemberSelfTaggedUnits.filter(u => u.unitType !== 'mission' && u.unitType !== 'nugget');

const groupMemberAssignedNonMissionUnits =
  groupMemberAssignedUnits.filter(u => u.unitType !== 'mission' && u.unitType !== 'nugget');



const topicSuggestions = await TopicSuggestion.find({
  suggestedBy: id,
  memberType: 'GroupMember'
}).sort({ submittedAt: -1 }).lean();


    
const [
  memberArticles,
  memberVideos,
  memberPromptSets,
  memberInterviews,
  memberExercises,
  memberTemplates,
  memberNuggets,
  memberMissions
] = await Promise.all([
  Article.find({ 'author.id': id }),
  Video.find({ 'author.id': id }),
  PromptSet.find({ 'author.id': id }),
  Interview.find({ 'author.id': id }),
  Exercise.find({ 'author.id': id }),
  Template.find({ 'author.id': id }),

  // ✅ IMPORTANT: nuggets + missions use createdBy / created_by
  Nugget.find({ createdBy: id }),
  Mission.find({ created_by: id })
]);

const memberUpcomings = await Upcoming.find({ createdBy: id });

const viewPathForLibraryUnit = (unitType, unitId) => {
  if (unitType === 'nugget') return `/unitviews/nuggets/view/${unitId}`;
  if (unitType === 'mission') return `/unitviews/missions/view/${unitId}`;
  if (unitType === 'upcoming') return `/unitviews/upcoming/view/${unitId}`;
  return `/unitviews/${unitType}s/view/${unitId}`;
};

const buildLibraryUnitRow = async (unit, unitType) => {
  const author = await resolveAuthorById(unit.author?.id || unit.author || id);

  return {
    unitType,
    displayType: unitType,
    title:
      unit.article_title ||
      unit.video_title ||
      unit.promptset_title ||
      unit.interview_title ||
      unit.exercise_title ||
      unit.template_title ||
      unit.title ||
      unit.mission_title ||
      'Untitled Unit',
    status: unit.status || 'Unknown',
    mainTopic:
      unit.main_topic ||
      unit.discipline ||
      unit.client ||
      unit.region ||
      'No topic',
    _id: unit._id,
    author: author.name,
    authorImage: author.image,
    viewPath: viewPathForLibraryUnit(unitType, unit._id)
  };
};

let groupMemberUnits = await Promise.all([
  ...memberArticles.map(unit => buildLibraryUnitRow(unit, 'article')),
  ...memberVideos.map(unit => buildLibraryUnitRow(unit, 'video')),
  ...memberPromptSets.map(unit => buildLibraryUnitRow(unit, 'promptset')),
  ...memberInterviews.map(unit => buildLibraryUnitRow(unit, 'interview')),
  ...memberExercises.map(unit => buildLibraryUnitRow(unit, 'exercise')),
  ...memberTemplates.map(unit => buildLibraryUnitRow(unit, 'template')),
  ...memberNuggets.map(unit => buildLibraryUnitRow(unit, 'nugget')),
  ...memberMissions.map(unit => buildLibraryUnitRow(unit, 'mission'))
]);

const myAuthor = await resolveAuthorById(id);

const myUpcomingRows = (memberUpcomings || []).map((u) => ({
  unitType: 'upcoming',
  displayType: u.unit_type ? `upcoming (${u.unit_type})` : 'upcoming',
  plannedType: u.unit_type,
  title: u.title || 'Untitled upcoming',
  status: u.status || 'in production',
  mainTopic: u.main_topic || 'No topic',
  _id: u._id,
  projectedRelease: u.projected_release_at,
  author: myAuthor.name,
  authorImage: myAuthor.image,
  viewPath: viewPathForLibraryUnit('upcoming', u._id)
}));

groupMemberUnits = [...groupMemberUnits, ...myUpcomingRows];




const registeredPromptSets = req.session.registeredPromptSets || [];

console.log("Registered prompt sets:", registeredPromptSets);

console.log("Progress data is now fully database-driven.");

console.log("Session updates are now minimal and only used for UI display.");

console.log("Progress is now retrieved dynamically from MongoDB.");



// Save the session explicitly - make sure it is saved explicitly so that notes can be posted for the member
req.session.save(err => {
    if (err) {
        console.error("Error saving session:", err);
    } else {
        console.log("SESSION UPDATED SUCCESSFULLY:", JSON.stringify(req.session, null, 2));
    }
});



// ---- Unified progress/completion build (deduped) ----

// Constants: Prompt0 + Prompts1–20
const TOTAL_PROMPTS = 21;

// 1) Fetch COMPLETED sets for this member, build exclusion set
const completedRecords = await PromptSetCompletion
  .find({ memberId: id })
  .populate('promptSetId');

const completedIds = new Set(
  completedRecords
    .map(r => r.promptSetId?._id?.toString())
    .filter(Boolean)
);

// 2) Fetch PROGRESS rows once
const progressRecords = await PromptSetProgress
  .find({ memberId: id })
  .populate('promptSetId');

// 3) Build CURRENT (deduped) from progress only, excluding completed
const currentByPsId = new Map();

for (const record of progressRecords) {
  const ps = record.promptSetId;
  if (!ps) continue;

const psId = ps._id.toString();
if (completedIds.has(psId)) continue; // exclude completed

const taggedPrompt = taggedPromptSetById.get(psId);

if (
  isArchivedCompletedPromptSet(psId) ||
  (taggedPrompt?.tagId && isArchivedDashboardItem(taggedPrompt.tagId, psId, id))
) {
  continue;
}



const completedCount = Array.isArray(record.completedPrompts)
  ? record.completedPrompts.length
  : 0;

// Use TOTAL_PROMPTS=21 consistently (Prompt0 + 1–20)
const progressPct = Math.round((completedCount / TOTAL_PROMPTS) * 100);
  const currentPromptIndex = Number.isInteger(record.currentPromptIndex)
    ? record.currentPromptIndex
    : 0;

  // Deduped insert (progress is source of truth for "current")
  if (!currentByPsId.has(psId)) {
    currentByPsId.set(psId, {
      promptSetId: psId,
      promptSetTitle: ps.promptset_title,
      frequency: ps.suggested_frequency,
      progress: `${progressPct}%`,
      targetCompletionDate: ps.target_completion_date || "Not Set",
      promptIndex: currentPromptIndex
    });
  }
}

// 4) Map COMPLETED sets for display (single pass)
const formattedCompletedSets = completedRecords
  .map(record => {
    const ps = record.promptSetId;
    const psId = ps?._id?.toString();

    if (!psId) return null;

    const taggedPrompt = taggedPromptSetById.get(psId);

if (
  isArchivedCompletedPromptSet(psId) ||
  (taggedPrompt?.tagId && isArchivedDashboardItem(taggedPrompt.tagId, psId, id))
) {
  return null;
}
return {
  completionId: record._id.toString(),
  promptSetId: psId,
  tagId: taggedPrompt?.tagId || null,
  assignedToId: id,

  promptSetTitle: ps?.promptset_title || 'Unknown Title',
  frequency: ps?.suggested_frequency,
  mainTopic: ps?.main_topic || 'No Topic',
  completedAt: record.completedAt
    ? new Date(record.completedAt).toDateString()
    : 'Unknown Date',
  badge: record.earnedBadge
};
  })
  .filter(Boolean);

// 5) Final arrays (sorted) to render
currentPromptSets = Array.from(currentByPsId.values())
  .sort((a, b) => a.promptSetTitle.localeCompare(b.promptSetTitle));

console.log("Group Member Prompts Data:", JSON.stringify(groupmemberPrompts, null, 2));
console.log("All session keys before rendering:", Object.keys(req.session));


console.log("Group Data for Leader Lookup:", JSON.stringify(leaderDoc, null, 2));
const leader = leaderDoc;

console.log("✅ Final Leader Name Before Rendering:", leader ? leader.groupLeaderName : "Not Found");

const groupMemberProfile = await GroupMemberProfile
  .findOne({ groupMemberId: id })
  .select('profileImage')
  .lean();



const emailPreferenceLevel = [1, 2].includes(Number(userData?.emailPreferenceLevel))
  ? Number(userData.emailPreferenceLevel)
  : 1;

const groupMemberAccount = {
  name: userData?.name || '',
  email: userData?.email || '',
  username: userData?.username || ''
};

// 👇 build "my group's library units" (other members in my group)
// 👇 build "my group's library units" including other group members + leader
// 👇 build "my group's library units" including other group members + leader
const otherMemberIds = (leaderDoc?.members || [])
  .map(m => m._id)
  .filter(mid => String(mid) !== String(id));

const groupAuthorIds = [
  ...otherMemberIds,
  leaderDoc._id
];

const [
  groupArticles2,
  groupVideos2,
  groupPromptSets2,
  groupInterviews2,
  groupExercises2,
  groupTemplates2,
  groupNuggets2,
  groupMissions2,
  groupUpcomings2
] = await Promise.all([
  Article.find({ 'author.id': { $in: groupAuthorIds } }),
  Video.find({ 'author.id': { $in: groupAuthorIds } }),
  PromptSet.find({ 'author.id': { $in: groupAuthorIds } }),
  Interview.find({ 'author.id': { $in: groupAuthorIds } }),
  Exercise.find({ 'author.id': { $in: groupAuthorIds } }),
  Template.find({ 'author.id': { $in: groupAuthorIds } }),

  // ✅ IMPORTANT: nuggets + missions use createdBy / created_by
  Nugget.find({ createdBy: { $in: groupAuthorIds } }),
  Mission.find({ created_by: { $in: groupAuthorIds } }),

  Upcoming.find({ createdBy: { $in: groupAuthorIds } })
]);

const buildGroupLibraryUnitRow = async (unit, unitType) => {
  const authorId = unit.author?.id || unit.author || unit.createdBy;
  const author = await resolveAuthorById(authorId);

  return {
    author: author.name,
    authorImage: author.image,

    unitType,
    displayType: unitType,

    title:
      unit.article_title ||
      unit.video_title ||
      unit.promptset_title ||
      unit.interview_title ||
      unit.exercise_title ||
      unit.template_title ||
      unit.title ||
      unit.mission_title ||
      'Untitled Unit',

    status: unit.status || 'Unknown',

    mainTopic:
      unit.main_topic ||
      unit.discipline ||
      unit.client ||
      unit.region ||
      'No topic',

    _id: unit._id,

    projectedRelease: unit.projected_release_at || null,

    viewPath:
      unitType === 'nugget'
        ? `/unitviews/nuggets/view/${unit._id}`
        : unitType === 'mission'
          ? `/unitviews/missions/view/${unit._id}`
          : unitType === 'upcoming'
            ? `/unitviews/upcoming/view/${unit._id}`
            : `/unitviews/${unitType}s/view/${unit._id}`
  };
};

let groupLibraryUnits = await Promise.all([
  ...groupArticles2.map(unit => buildGroupLibraryUnitRow(unit, 'article')),
  ...groupVideos2.map(unit => buildGroupLibraryUnitRow(unit, 'video')),
  ...groupPromptSets2.map(unit => buildGroupLibraryUnitRow(unit, 'promptset')),
  ...groupInterviews2.map(unit => buildGroupLibraryUnitRow(unit, 'interview')),
  ...groupExercises2.map(unit => buildGroupLibraryUnitRow(unit, 'exercise')),
  ...groupTemplates2.map(unit => buildGroupLibraryUnitRow(unit, 'template')),
  ...groupNuggets2.map(unit => buildGroupLibraryUnitRow(unit, 'nugget')),
  ...groupMissions2.map(unit => buildGroupLibraryUnitRow(unit, 'mission'))
]);

const gmUpcomingRows2 = await Promise.all(
  (groupUpcomings2 || []).map(async (u) => {
    const author = await resolveAuthorById(u.createdBy);

    return {
      author: author?.name || 'Group Member',
      authorImage: author?.image || '/images/default-avatar.png',
      unitType: 'upcoming',
      plannedType: u.unit_type,
      title: u.title || 'Untitled upcoming',
      status: u.status || 'in production',
      mainTopic: u.main_topic || 'No topic',
      _id: u._id,
      projectedRelease: u.projected_release_at,
      viewPath: `/unitviews/upcoming/view/${u._id}`
    };
  })
);

groupLibraryUnits = [...groupLibraryUnits, ...gmUpcomingRows2];





// Build current counts from arrays you already computed above
const gmCounts = {
  group: (leaderDoc?.members || []).length,
  topics: (topicSuggestions || []).length,

  prompts: (memberRegistrations || []).length + (assignedPromptSets || []).length,

  progress: (formattedCompletedSets || []).length,

  library: (groupMemberUnits || []).length,

  // learning and assignments = normal units only
  tagged: (groupMemberSelfTaggedNonMissionUnits || []).length
        + (groupMemberAssignedNonMissionUnits || []).length,

  // nuggets and missions tab = nuggets + missions only
  missions: (groupMemberTaggedNuggets || []).length
          + (groupMemberAssignedNuggets || []).length
          + (groupMemberTaggedMissions || []).length
          + (groupMemberAssignedMissions || []).length
};

// Load/create seen doc for this group member
// Load/create seen doc for this group member
let seenDocGM = await DashboardSeen.findOne({ userId: id, role: 'group_member' });

if (!seenDocGM) {
  // First time: baseline all tabs to current counts (no dots on first render)
  seenDocGM = new DashboardSeen({ userId: id, role: 'group_member', tabs: new Map() });
}

// ✅ make tabs Map-like even if older docs stored it as an object
ensureTabsMap(seenDocGM);

// First time OR existing: baseline any missing tabs once
let updated = false;

for (const [key, val] of Object.entries(gmCounts)) {
  const hasKey =
    seenDocGM.tabs && typeof seenDocGM.tabs.has === 'function'
      ? seenDocGM.tabs.has(key)
      : false;

  if (!hasKey) {
    seenDocGM.tabs.set(key, { count: val, seenAt: new Date() });
    updated = true;
  }
}

// If doc was new or we added tabs, save it
if (updated || seenDocGM.isNew) {
  await seenDocGM.save();
}

// Compute badges: show dot ONLY if current > lastSeen
const gmBadges = {};
for (const [key, val] of Object.entries(gmCounts)) {
  const last = seenDocGM.tabs.get(key)?.count ?? val; // default to current as baseline
  gmBadges[key] = val > last;
}


const group = {
  ...leaderDoc,
  groupImage: groupProfileDoc?.groupImage || '/images/defaultgroupavatar.jpg'
};

// ✅ Final render
return res.render('groupmember_dashboard', {
  layout: 'dashboardlayout',
  title: 'Group Member Dashboard',
  csrfToken: safeCsrfToken(req),

  mfaStatus,

  user: {
    ...groupMemberObj,
    termsAccepted: !!userData?.termsAccepted
  },

  groupMember: {
    ...groupMemberObj,
    profileImage: groupMemberProfile?.profileImage || '/images/default-avatar.png'
  },
  group,
  groupMembers,
  maxGroupSize: leaderDoc.groupSize,
  groupMemberUnits,
  registeredPromptSets: groupmemberPrompts,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,
  selectedTopics,
  leaderName: leader ? leader.groupLeaderName : "Group Leader",
organization: leader?.organizationName || '',
  topicSuggestions,
  groupMemberAccount,
  emailPreferenceLevel,
  groupLibraryUnits,
  missionBadges,

  groupMemberSelfTaggedUnits,
  groupMemberAssignedUnits,
  groupMemberTaggedNuggets,
  groupMemberAssignedNuggets,
  groupMemberTaggedMissions,
  groupMemberAssignedMissions,
  groupMemberSelfTaggedNonMissionUnits,
  groupMemberAssignedNonMissionUnits,

  gmCounts,
  gmBadges
});



        
        
        
        
        } catch (err) {
            console.error('Error rendering group member dashboard:', err.stack || err);

            return res.status(500).render('error', { title: 'Error', errorMessage: 'An unexpected error occurred.' });
        }
    },


// --- POST /dashboard/groupmember/account/email-preferences ---
updateEmailPreferences: async (req, res) => {
  try {
    const memberId = req.session?.user?.id;
    if (!memberId) return res.redirect('/auth/login');

    let level = parseInt(req.body.email_preference_level, 10);
    if (![1, 2].includes(level)) level = 1;

    const result = await GroupMember.findByIdAndUpdate(
      memberId,
      { $set: { emailPreferenceLevel: level, emailPreferencesUpdatedAt: new Date() } },
      { new: false }
    );

    console.log('✅ GroupMember email prefs updated:', { memberId, level, ok: !!result });

    // Render success page (same look/feel as leader/member)
    return res.render('partials/dashboardpartials/emailpreferencessuccess', {
      layout: 'dashboardlayout',
      title: 'Email Preferences Updated',
      emailPreferenceLevel: level,
      dashboard: req.baseUrl || '/dashboard/groupmember'
    });
  } catch (err) {
    console.error('updateEmailPreferences (group member) error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'mainlayout',
      title: 'Error',
      errorMessage: 'Could not update email preferences. Please try again.'
    });
  }
},

// --- POST /dashboard/groupmember/account/details ---
updateAccountDetails: async (req, res) => {
  try {
    const memberId = req.session?.user?.id;
    if (!memberId) return res.redirect('/auth/login');

    const { name, email, username } = req.body || {};
    const updates = {};

    if (typeof name === 'string' && name.trim()) updates.name = name.trim();
    if (typeof email === 'string' && email.trim()) updates.email = email.trim();
    if (typeof username === 'string') updates.username = username.trim();

    const changedCount = Object.keys(updates).length;

    if (changedCount) {
      await GroupMember.findByIdAndUpdate(memberId, { $set: updates });
      console.log('✅ GroupMember account updated:', { memberId, updates });
    } else {
      console.log('ℹ️ No account fields changed for GroupMember:', memberId);
    }

    // Render success page for visual confirmation
    return res.render('partials/dashboardpartials/accountdetailssuccess', {
      layout: 'dashboardlayout',
      title: 'Account Updated',
      dashboard: req.baseUrl || '/dashboard/groupmember',
      changedCount,
      // Only echo changed values
      name: updates.name,
      email: updates.email,
      username: updates.username
    });
  } catch (err) {
    console.error('updateAccountDetails (group member) error:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'mainlayout',
      title: 'Error',
      errorMessage: 'Could not update account details. Please try again.'
    });
  }
}
,
// --- POST /dashboard/groupmember/seen ---
markGroupMemberTabSeen: async (req, res) => {
  try {
    const memberId = req.session?.user?.id;

    if (!memberId) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    const allowedTabs = new Set([
      'group',
      'topics',
      'prompts',
      'progress',
      'tagged',
      'missions',
      'library'
    ]);

    const tabKey = req.body?.tab || req.body?.tabKey;
    const currentCount = Number(req.body?.count ?? req.body?.currentCount ?? 0);

    if (!tabKey) {
      return res.status(400).json({ ok: false, error: 'missing tab key' });
    }

    if (!allowedTabs.has(tabKey)) {
      return res.status(400).json({ ok: false, error: 'invalid tab key' });
    }

    let seenDoc = await DashboardSeen.findOne({
      userId: memberId,
      role: 'group_member'
    });

    if (!seenDoc) {
      seenDoc = new DashboardSeen({
        userId: memberId,
        role: 'group_member',
        tabs: new Map()
      });
    }

    ensureTabsMap(seenDoc);

    seenDoc.tabs.set(tabKey, {
      count: Number.isFinite(currentCount) ? currentCount : 0,
      seenAt: new Date()
    });

    seenDoc.markModified('tabs');

    await seenDoc.save();

    return res.json({
      ok: true,
      tab: tabKey,
      count: Number.isFinite(currentCount) ? currentCount : 0
    });

  } catch (e) {
    console.error('markGroupMemberTabSeen error:', e);
    return res.status(500).json({ ok: false });
  }
},




};







