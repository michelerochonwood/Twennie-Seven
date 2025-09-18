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







async function resolveAuthorById(authorId) {
    try {
        // Leader profile
        let profile = await LeaderProfile.findOne({ leaderId: authorId }).select('profileImage name');
        if (profile) return { name: profile.name || 'Leader', image: profile.profileImage || '/images/default-avatar.png' };

        // Group member profile
        profile = await GroupMemberProfile.findOne({ memberId: authorId }).select('profileImage name');
        if (profile) return { name: profile.name || 'Group Member', image: profile.profileImage || '/images/default-avatar.png' };
    } catch (err) {
        console.error('resolveAuthorById failed:', err);
    }

    return { name: 'Unknown Author', image: '/images/default-avatar.png' };
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



const getModelByUnitType = (type) => {
  switch (type) {
    case 'article':   return Article;
    case 'video':     return Video;
    case 'interview': return Interview;
    case 'exercise':  return Exercise;
    case 'template':  return Template;
    case 'upcoming':  return Upcoming; // 👈 add upcoming
    default:          return null;
  }
};

async function buildLeaderAssignedUnits(leaderId) {
  const assignedTags = await Tag.find({
    createdBy: leaderId,
    assignedTo: { $exists: true, $ne: [] },
  }).lean();

  const leaderAssignedUnits = [];

  for (const tag of assignedTags) {
    for (const { item, unitType } of tag.associatedUnits || []) {
      // skip types you don't want here
      if (unitType === 'promptset' || unitType === 'prompt') continue;

      const Model = getModelByUnitType(unitType);
      if (!Model) continue;

      const unit = await Model.findById(item).lean();
      if (!unit) continue;

      for (const assignee of tag.assignedTo) {
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
          assignedTo: {
            _id: assignee.member?.toString(),
            name: member.name,
            instructions: assignee.instructions || '',
            completedAt: assignee.completedAt || null, // ← KEY: timestamp or null
          }
        });
      }
    }
  }

  return leaderAssignedUnits;
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
    'Conducting Color Reviews of Proposals': 'conductingcolorreviews',
    'Storytelling in Technical Marketing': 'storytellingintechnicalmarketing',
    'Client Experience': 'clientexperience',
    'Social Media, Advertising, and Other Mysteries': 'socialmediaadvertisingandothermysteries',
    'Pull Marketing': 'pullmarketing',
    'Emotional Intelligence': 'emotionalintelligence',
    'People Before Profit': 'peoplebeforeprofit',
    'Non-Technical Roles in Technical Environments': 'nontechnicalrolesintechnicalenvironments',
    'Leadership in Technical Services': 'leadershipintechnicalservices',
    'Leading Change': 'leadingchange',
    'Leading Groups on Twennie': 'leadinggroupsontwennie',
    'The Advantage of Failure': 'theadvantageoffailure',
    'Social Entrepreneurship': 'socialentrepreneurship',
    'Employee Experience': 'employeeexperience',
    'Project Management Software': 'projectmanagementsoftware',
    'CRM Platforms': 'crmplatforms',
    'Client Feedback Software': 'clientfeedbacksoftware',
    'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
    'Remote or Hybrid Work': 'remoteorhybridwork',
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
            const leaderProfile = await LeaderProfile.findOne({ leaderId: id }).select('profileImage');

            const topicSuggestions = await TopicSuggestion.find({
            suggestedBy: id,
            memberType: 'Leader' // This ensures it's scoped to leaders only

}).sort({ submittedAt: -1 }).lean();
            const resolvedGroupMembers = await Promise.all(
  (userData.members || []).map(async (member) => {
    const profile = await GroupMemberProfile.findOne({ memberId: member._id }).select('profileImage');
    return {
      ...member,
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
    const author = await resolveAuthorById(unit.author.id);
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



            
            console.log("All session keys before rendering:", Object.keys(req.session));
            // Attach subtopics and slugs for the leader's topics
const selectedTopics = {
    topic1: {
        title: leader.topics.topic1,
        subtopics: getSubtopics(leader.topics.topic1),
        slug: topicMappings[leader.topics.topic1] || 'unknown-topic',
        viewName: topicViewMappings[topicMappings[leader.topics.topic1]] || 'not_found'
    },
    topic2: {
        title: leader.topics.topic2,
        subtopics: getSubtopics(leader.topics.topic2),
        slug: topicMappings[leader.topics.topic2] || 'unknown-topic',
        viewName: topicViewMappings[topicMappings[leader.topics.topic2]] || 'not_found'
    },
    topic3: {
        title: leader.topics.topic3,
        subtopics: getSubtopics(leader.topics.topic3),
        slug: topicMappings[leader.topics.topic3] || 'unknown-topic',
        viewName: topicViewMappings[topicMappings[leader.topics.topic3]] || 'not_found'
    }
};

console.log("Selected Topics for Leader:", selectedTopics);

            

const allLeaderTaggedUnits = await fetchTaggedUnits(id);

// Only self-tags (no assignments) count toward "my tagged units"
const leaderTaggedUnits = allLeaderTaggedUnits.filter(u => u.assignedCount === 0);
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
    const author = await resolveAuthorById(unit.author.id);
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

const leaderAssignedUnits = await buildLeaderAssignedUnits(id);
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


return res.render('leader_dashboard', {
  layout: 'dashboardlayout',
  title: 'Leader Dashboard',
  csrfToken: req.csrfToken(),
  leader: {
    ...userData,
    profileImage: leaderProfile?.profileImage || '/images/default-avatar.png'
  },
  leaderGroupMembers: resolvedGroupMembers,
  maxGroupSize: userData.maxGroupSize,
  leaderUnits,
  groupMemberUnits,
  leaderTaggedUnits,
  leaderAssignedUnits,
  registeredPromptSets: leaderPrompts,
  promptSchedules,
  currentPromptSets,
  completedPromptSets: formattedCompletedSets,
  selectedTopics,
  topicSuggestions,
  leaderAccount,
  emailPreferenceLevel,

  // 👇 add this line
  mfaStatus,
  leaderCounts,     // 👈 NEW
  leaderBadges,     // 👈 NEW
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



