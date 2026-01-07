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
        profile = await GroupMemberProfile.findOne({ memberId: authorId }).select('profileImage name');
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
    'Leading Groups on Twennie': 'leadinggroupsontwennie',
    'Leading Change': 'leadingchange',
    'The Advantage of Failure': 'theadvantageoffailure',
    'Social Entrepreneurship': 'socialentrepreneurship',
    'Employee Experience': 'employeeexperience',
    'Project Management Software': 'projectmanagementsoftware',
    'CRM Platforms': 'crmplatforms',
    'Client Feedback Software': 'clientfeedbacksoftware',
    'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
'Remote and Hybrid Work': 'remoteandhybridwork',
    'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
    'The Power of Purpose': 'thepowerofpurpose',
    'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading',
    'Team Building in Technical Consulting': 'teambuildingintechnicalconsulting',
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
    'crmplatforms': 'single_topic_crm',
    'emotionalintelligence': 'single_topic_emotionali',
    'employeeexperience': 'single_topic_employeeex',
    'theadvantageoffailure': 'single_topic_failure',
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
'programmanagement': 'single_topic_program',
'makingaproposaleasytoreadskimandevaluate': 'single_topic_readskim',
    'theparetoprinciple': 'single_topic_pareto',
    'peoplebeforeprofit': 'single_topic_peoplebefore',
    'thepowerofplayintheworkplace': 'single_topic_play',
    'projectmanagementsoftware': 'single_topic_pmsoftware',
    'projectmanagement': 'single_topic_projectmgmt',
    'proposalmanagement': 'single_topic_proposalmgmt',
    'proposalstrategy': 'single_topic_proposalstrat',
    'designingaproposalprocess': 'single_topic_proposalprocess',
    'conductingcolorreviews': 'single_topic_colorreviews',
    'remoteandhybridwork': 'single_topic_remote',
    'socialentrepreneurship': 'single_topic_social',
    'socialmediaadvertisingandothermysteries': 'single_topic_socialmedia',
    'softskillsintechnicalenvironments': 'single_topic_softskills',
    'storytellingintechnicalmarketing': 'single_topic_storytelling',
    'teambuildinginconsulting': 'single_topic_teambuilding',
    'pullmarketing': 'single_topic_pullmarketing',
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
        return {
          unitType: type,
          title: unit[titleField] || `Untitled ${type}`,
          mainTopic: unit[topicField] || 'No topic',
          _id: unit._id,
          tagId: tag?._id?.toString() || null,
          tagIdCreator: tag?.createdBy?.toString() || null, // used to split self vs leader-assigned
          instructions: assignment?.instructions || '',
          completedAt: assignment?.completedAt || null,
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

module.exports = {
    renderGroupMemberDashboard: async (req, res) => {

        try {
            const { id } = req.session.user;


let currentPromptSets = [];

let completedPromptSets = [];



            console.log("Fetching dashboard for user:", id);

            //members of a group are meant to show in the group member dashboard as cards - it is important that none of this changed because the group members are located based on the leader of the group - if you are rewriting anything in this renderdashboard, make sure to rewrite it exactly as you see it here. 
    
const userData = await GroupMember.findById(id)
  .select('name email username profileImage professionalTitle organization groupId emailPreferenceLevel mfa.enabled mfa.method mfa.recoveryCodes mfa.updatedAt')
  .populate({
    path: 'groupId',
    populate: { path: 'members', model: 'GroupMember', select: 'name profileImage professionalTitle' }
  });

  // ✅ Pull the group's image from GroupProfile and attach it to the populated groupId
const groupProfileDoc = await GroupProfile
  .findOne({ groupId: userData.groupId?._id })
  .select('groupImage')
  .lean();

// We will build a plain object for groupMember to guarantee the extra field is present
const groupMemberObj = userData.toObject();
if (!groupMemberObj.groupId) groupMemberObj.groupId = {};
groupMemberObj.groupId.groupImage = groupProfileDoc?.groupImage || groupMemberObj.groupId.groupImage || '/images/defaultgroupavatar.jpg';


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
if (!userData) {
  console.error(`Group Member with ID ${id} not found.`);
  return res.status(404).render('error', {
    title: 'Error',
    errorMessage: `Group Member with ID ${id} not found.`
  });
}

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
  (userData.groupId && typeof userData.groupId.topics === 'object')
    ? userData.groupId.topics
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
  JSON.stringify(userData.groupId?.members || [], null, 2)
);

// ✅ Resolve each member's avatar from GroupMemberProfile
// ✅ Resolve avatars from GroupMemberProfile to ensure pictures show up
let groupMembers = [];
if (Array.isArray(userData.groupId?.members) && userData.groupId.members.length > 0) {
  groupMembers = await Promise.all(
    userData.groupId.members.map(async (m) => {
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
                        const leader = await Leader.findOne({ _id: userData.groupId._id }).select('groupLeaderName organization');


                        if (!leader) {
                            console.error("❌ ERROR: Leader not found for groupId:", userData.groupId);
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

// ✅ 1) Self-tagged (all unit types, including upcoming + nuggets)
const groupMemberSelfTaggedUnits = allTaggedUnits
  .filter(u => u.tagIdCreator === id.toString());

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
const groupMemberAssignedUnits = assignedRaw.map(u => ({
  ...u,
  leaderName: leaderNameById.get(u.tagIdCreator) || 'Group Leader',
  assignedInstructions: u.instructions || '',
  assignedCompletedAtFormatted: u.completedAt ? new Date(u.completedAt).toLocaleDateString('en-CA', { year: 'numeric', month: 'short', day: '2-digit' }) : ''
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


    
const [memberArticles, memberVideos, memberPromptSets, memberInterviews, memberExercises, memberTemplates] = await Promise.all([
  Article.find({ 'author.id': id }),
  Video.find({ 'author.id': id }),
  PromptSet.find({ 'author.id': id }),
  Interview.find({ 'author.id': id }),
  Exercise.find({ 'author.id': id }),
  Template.find({ 'author.id': id })
]);

// 👇 my upcoming units (ownership via createdBy)
const memberUpcomings = await Upcoming.find({ createdBy: id });

let groupMemberUnits = await Promise.all(
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
      author: author.name,
      authorImage: author.image
    };
  })
);

// 👇 append my upcoming rows
const myUpcomingRows = (memberUpcomings || []).map((u) => ({
  unitType: 'upcoming',
  plannedType: u.unit_type,                 // e.g., 'video'
  title: u.title,
  status: u.status || 'in production',
  mainTopic: u.main_topic || 'No topic',
  _id: u._id,
  projectedRelease: u.projected_release_at
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
const formattedCompletedSets = completedRecords.map(record => ({
  promptSetTitle: record.promptSetId?.promptset_title || 'Unknown Title',
  frequency: record.promptSetId?.suggested_frequency,
  mainTopic: record.promptSetId?.main_topic || 'No Topic',
  completedAt: record.completedAt
    ? new Date(record.completedAt).toDateString()
    : "Unknown Date",
  badge: record.earnedBadge // { image, name }
}));

// 5) Final arrays (sorted) to render
currentPromptSets = Array.from(currentByPsId.values())
  .sort((a, b) => a.promptSetTitle.localeCompare(b.promptSetTitle));

console.log("Group Member Prompts Data:", JSON.stringify(groupmemberPrompts, null, 2));
console.log("All session keys before rendering:", Object.keys(req.session));


console.log("Group Data for Leader Lookup:", JSON.stringify(userData.groupId, null, 2));

const leader = await Leader.findOne({ _id: userData.groupId._id }).select('groupLeaderName');

console.log("✅ Final Leader Name Before Rendering:", leader ? leader.groupLeaderName : "Not Found");

const groupMemberProfile = await GroupMemberProfile.findOne({ groupMemberId: id }).select('profileImage');


const emailPreferenceLevel = [1, 2, 3].includes(Number(userData?.emailPreferenceLevel))
  ? Number(userData.emailPreferenceLevel)
  : 1;

const groupMemberAccount = {
  name: userData?.name || '',
  email: userData?.email || '',
  username: userData?.username || ''
};

// 👇 build "my group's library units" (other members in my group)
const otherMemberIds = (userData.groupId?.members || [])
  .map(m => m._id)
  .filter(mid => String(mid) !== String(id));

const [
  groupArticles2,
  groupVideos2,
  groupPromptSets2,
  groupInterviews2,
  groupExercises2,
  groupTemplates2,
  groupUpcomings2
] = await Promise.all([
  Article.find({ 'author.id': { $in: otherMemberIds } }),
  Video.find({ 'author.id': { $in: otherMemberIds } }),
  PromptSet.find({ 'author.id': { $in: otherMemberIds } }),
  Interview.find({ 'author.id': { $in: otherMemberIds } }),
  Exercise.find({ 'author.id': { $in: otherMemberIds } }),
  Template.find({ 'author.id': { $in: otherMemberIds } }),
  Upcoming.find({ createdBy: { $in: otherMemberIds } })
]);

let groupLibraryUnits = await Promise.all(
  [...groupArticles2, ...groupVideos2, ...groupPromptSets2, ...groupInterviews2, ...groupExercises2, ...groupTemplates2].map(async (unit) => {
    const author = await resolveAuthorById(unit.author?.id || unit.author);
    return {
      author: author.name,
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
      _id: unit._id
    };
  })
);

// 👇 append upcoming rows for other members
const gmUpcomingRows2 = await Promise.all(
  (groupUpcomings2 || []).map(async (u) => {
    const author = await resolveAuthorById(u.createdBy);
    return {
      author: author?.name || 'Group Member',
      unitType: 'upcoming',
      plannedType: u.unit_type,
      title: u.title,
      status: u.status || 'in production',
      mainTopic: u.main_topic || 'No topic',
      _id: u._id,
      projectedRelease: u.projected_release_at
    };
  })
);

groupLibraryUnits = [...groupLibraryUnits, ...gmUpcomingRows2];






// Build current counts from arrays you already computed above
const gmCounts = {
  group:    (userData.groupId?.members || []).length, // my group members
  topics:   (topicSuggestions || []).length,          // my suggested topics

  // prompts: both self-registered + assigned to me
  prompts:  (memberRegistrations || []).length + (assignedPromptSets || []).length,

  // progress: completed sets count
  progress: (formattedCompletedSets || []).length,

  // library: my contributions (incl. upcoming)
  library:  (groupMemberUnits || []).length,

  // tagged: self-tagged + leader-assigned (all types, incl nuggets + missions)
  tagged:   (groupMemberSelfTaggedUnits || []).length
          + (groupMemberAssignedUnits || []).length,

  // ✅ NEW: missions tab count (self-tagged + assigned missions)
  missions: (groupMemberTaggedMissions || []).length
          + (groupMemberAssignedMissions || []).length
};

// Load/create seen doc for this group member
let seenDocGM = await DashboardSeen.findOne({ userId: id, role: 'group_member' });

if (!seenDocGM) {
  // First time: baseline all tabs to current counts (no dots on first render)
  seenDocGM = new DashboardSeen({ userId: id, role: 'group_member', tabs: new Map() });
  for (const [key, val] of Object.entries(gmCounts)) {
    seenDocGM.tabs.set(key, { count: val, seenAt: new Date() });
  }
  await seenDocGM.save();
} else {
  // If new tabs were added later, baseline them once
  let updated = false;
  for (const [key, val] of Object.entries(gmCounts)) {
    if (!seenDocGM.tabs?.has(key)) {
      seenDocGM.tabs.set(key, { count: val, seenAt: new Date() });
      updated = true;
    }
  }
  if (updated) await seenDocGM.save();
}

// Compute badges: show dot ONLY if current > lastSeen
const gmBadges = {};
for (const [key, val] of Object.entries(gmCounts)) {
  const last = seenDocGM.tabs?.get(key)?.count ?? val; // default to current as baseline
  gmBadges[key] = val > last;
}

// ✅ Final render
return res.render('groupmember_dashboard', {
  layout: 'dashboardlayout',
  title: 'Group Member Dashboard',
  csrfToken: req.csrfToken(),

  mfaStatus,

groupMember: {
  ...groupMemberObj, // ✅ use the object we augmented with groupId.groupImage
  profileImage: groupMemberProfile?.profileImage || '/images/default-avatar.png'
},
groupMembers,
maxGroupSize: userData.groupId.groupSize,
  groupMemberUnits,
  registeredPromptSets: groupmemberPrompts,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,
  selectedTopics,
  leaderName: leader ? leader.groupLeaderName : "Group Leader",
  organization: leader?.organization || 'Unknown',
  topicSuggestions,
  groupMemberAccount,
  emailPreferenceLevel,
  groupLibraryUnits,
    missionBadges,

  // tagged / assigned unit buckets
  groupMemberSelfTaggedUnits,    // blended self-tagged, all types
  groupMemberAssignedUnits,      // blended leader-assigned, all types

  groupMemberTaggedNuggets,      // ✅ tagged nuggets
  groupMemberAssignedNuggets,    // ✅ assigned nuggets

  groupMemberTaggedMissions,     // ✅ tagged missions
  groupMemberAssignedMissions,   // ✅ assigned missions

  groupMemberSelfTaggedNonMissionUnits,
  groupMemberAssignedNonMissionUnits,

  // counts + badges for green dots
  gmCounts,
  gmBadges
});



        
        
        
        
        } catch (err) {
            console.error('Error rendering group member dashboard:', err);
            return res.status(500).render('error', { title: 'Error', errorMessage: 'An unexpected error occurred.' });
        }
    },


// --- POST /dashboard/groupmember/account/email-preferences ---
updateEmailPreferences: async (req, res) => {
  try {
    const memberId = req.session?.user?.id;
    if (!memberId) return res.redirect('/auth/login');

    let level = parseInt(req.body.email_preference_level, 10);
    if (![1, 2, 3].includes(level)) level = 1;

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
    if (!memberId) return res.status(401).json({ ok: false, error: 'unauthorized' });

    const { tabKey, currentCount } = req.body || {};
    if (!tabKey) return res.status(400).json({ ok: false, error: 'missing tabKey' });

    // Load/create doc
    let seenDoc = await DashboardSeen.findOne({ userId: memberId, role: 'group_member' });
    if (!seenDoc) {
      seenDoc = new DashboardSeen({ userId: memberId, role: 'group_member', tabs: new Map() });
    }

    // Update this tab with the current count and timestamp
    const countNum = Number(currentCount) || 0;
    seenDoc.tabs.set(tabKey, { count: countNum, seenAt: new Date() });
    await seenDoc.save();

    return res.json({ ok: true });
  } catch (e) {
    console.error('markGroupMemberTabSeen error:', e);
    return res.status(500).json({ ok: false });
  }
},




};







