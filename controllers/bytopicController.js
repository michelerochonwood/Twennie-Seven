const fs = require('fs');
const path = require('path');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const Promptset = require('../models/unit_models/promptset');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Member = require('../models/member_models/member');
const TopicSuggestion = require('../models/topic/topic_suggestion'); // Adjust the path as needed
const MemberProfile = require('../models/profile_models/member_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const Upcoming = require('../models/unit_models/upcoming'); 




// Resolves an author's display name and profile image based on their role.
// Leaders, Group Members, and Members are stored in separate models by design.
// Leaders use `groupLeaderName` instead of `name`, so we map it manually here for consistency.
async function resolveAuthorById(authorId) {
  try {
    // Leader profile by leaderId
    let profile = await LeaderProfile.findOne({ leaderId: authorId })
      .select('profileImage name')
      .lean();
    if (profile) {
      return {
        name: profile.name || 'Leader',
        image: normalizeImg(profile.profileImage)
      };
    }

    // Group Member profile by groupMemberId  ✅ FIXED KEY
    profile = await GroupMemberProfile.findOne({ groupMemberId: authorId })
      .select('profileImage name')
      .lean();
    if (profile) {
      return {
        name: profile.name || 'Group Member',
        image: normalizeImg(profile.profileImage)
      };
    }

    // Individual Member profile by memberId
    profile = await MemberProfile.findOne({ memberId: authorId })
      .select('profileImage name')
      .lean();
    if (profile) {
      return {
        name: profile.name || 'Member',
        image: normalizeImg(profile.profileImage)
      };
    }
  } catch (error) {
    console.error('Error resolving author profile:', error);
  }

  return { name: 'Unknown Author', image: '/images/default-avatar.png' };
}

// Ensure local paths are absolute (handles '/uploads/...' vs 'uploads/...')
function normalizeImg(img) {
  if (!img) return '/images/default-avatar.png';
  if (/^https?:\/\//i.test(img)) return img;
  return img.startsWith('/') ? img : `/${img}`;
}



exports.getTopicView = async (req, res) => {

    const normalizedTopic = req.params.id.toLowerCase().replace(/[^a-z0-9]/g, '');
    const topicsFilePath = path.join(__dirname, '../public/data/topics.json');

    try {
        if (!fs.existsSync(topicsFilePath)) {
            console.error('Topics file is missing.');
            return res.status(404).send('Topics file is missing.');
        }

        const topicsData = JSON.parse(fs.readFileSync(topicsFilePath, 'utf8'));
        if (!Array.isArray(topicsData.topics)) {
            throw new Error('Invalid topics.json format: "topics" should be an array.');
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
            'Conducting Color Reviews of Proposals': 'conductingcolorreviewsofproposals',
            'Candid Communication': 'candidcommunication',
            'Client Interactions': 'clientinteractions',
            'Cross Selling in Multi-Disciplinary Firms': 'crosssellinginmultidisciplinaryfirms',
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
            'CRM Software': 'crmsoftware',
            'Client Feedback Software': 'clientfeedbacksoftware',
            'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
            'Remote and Hybrid Work': 'remoteandhybridwork',
            'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
            'The Power of Purpose': 'thepowerofpurpose',
            'Tips and Tricks for Proposal Proofreading': 'tipsandtricksforproposalproofreading',
            'Team Building in Technical Consulting': 'teambuilding',
            'When the Workload is Light': 'whentheworkloadislight',
            'The First 10 Days of a Project': 'thefirst10daysofaproject',
            'Managing Scope So It Doesnt Manage You': 'managingscopesoitdoesntmanageyou',
            'Risk Management': 'riskmanagement',
            'Closing a Project Strategically': 'closingaprojectstrategically',
            'Rescuing a Project That Has Gone Off the Rails': 'rescuingaprojectthatsgoneofftherails'
        };

        const originalTopicTitle = Object.keys(topicMappings).find(
            (title) => topicMappings[title] === normalizedTopic
        );

        if (!originalTopicTitle) {
            console.error(`Topic not found for normalized title: ${normalizedTopic}`);
            return res.status(404).send('Topic not found.');
        }

        console.log(`Resolved Topic Title: ${originalTopicTitle}`);

        const topic = topicsData.topics.find((t) => t.title === originalTopicTitle);
        if (!topic) {
            console.error(`Topic data missing for title: ${originalTopicTitle}`);
            return res.status(404).send('Topic data not found.');
        }

        // Search for units where the topic is in main_topic or secondary_topics
        const queryCondition = { 
            $or: [
                { main_topic: topic.title }, 
                { secondary_topics: topic.title }  // Replaced sub_topics with secondary_topics
            ]
        };
        console.log(`Query Condition:`, JSON.stringify(queryCondition, null, 2));

const [articles, videos, interviews, promptsets, exercises, templates, upcomings] = await Promise.all([
  Article.find(queryCondition).lean(),
  Video.find(queryCondition).lean(),
  Interview.find(queryCondition).lean(),
  Promptset.find(queryCondition).lean(),
  Exercise.find(queryCondition).lean(),
  Template.find(queryCondition).lean(),
  Upcoming.find(queryCondition).lean(),
]);

        console.log(`Found Articles: ${articles.length}`);
        console.log(`Found Videos: ${videos.length}`);
        console.log(`Found Interviews: ${interviews.length}`);
        console.log(`Found Promptsets: ${promptsets.length}`);
        console.log(`Found Exercises: ${exercises.length}`);
        console.log(`Found Templates: ${templates.length}`);
        console.log(`Found Upcoming: ${upcomings.length}`);

const allUnits = [
  ...articles.map((unit) => ({ title: unit.article_title, ...unit, type: 'article', authorId: unit.author?.id || unit.author })),
  ...videos.map((unit) => ({ title: unit.video_title, ...unit, type: 'video', authorId: unit.author?.id || unit.author })),
  ...interviews.map((unit) => ({ title: unit.interview_title, ...unit, type: 'interview', authorId: unit.author?.id || unit.author })),
  ...promptsets.map((unit) => ({
    title: unit.promptset_title,
    ...unit,
    type: 'promptset',
    authorId: unit.author?.id || unit.author,
    targetAudience: unit.target_audience,
    characteristics: unit.characteristics,
    purpose: unit.purpose,
    suggestedFrequency: unit.suggested_frequency,
  })),
  ...exercises.map((unit) => ({ title: unit.exercise_title, ...unit, type: 'exercise', authorId: unit.author?.id || unit.author })),
  ...templates.map((unit) => ({ title: unit.template_title, ...unit, type: 'template', authorId: unit.author?.id || unit.author })),
  // ← NEW: UPCOMING
  ...upcomings.map((u) => ({
  title: u.title,
  ...u,
  type: 'upcoming',
  unit_type: u.unit_type,                           // planned type
  authorId: u.author?.id || u.author || u.createdBy || null, // 👈 add createdBy fallback
  visibility: u.visibility || 'all_members'
})),
];

        console.log(`Total Processed Units: ${allUnits.length}`);

const libraryUnits = await Promise.all(
  allUnits.map(async (unit) => {
    const authorId =
      unit.authorId ||               // 👈 prefer the normalized field
      unit.author?.id ||
      unit.author ||
      null;

    const author = authorId
      ? await resolveAuthorById(authorId)
      : { name: 'Unknown Author', image: '/images/default-avatar.png' };

    return {
      ...unit,
      authorName: author.name,
      authorImage: author.image || '/images/default-avatar.png',
    };
  })
);

//
// ---- BEGIN: smarter segmentation by authorship + visibility ----
const userId = req.user?.id || req.session.user?.id || null;

// Helper: normalize org keys consistently
const normalize = (s) => (s || '').toString().trim().toLowerCase();
const emailDomain = (e) => {
  if (!e || !e.includes('@')) return null;
  return e.split('@').pop().toLowerCase();
};

// Load current user and derive group + org context
let leaderDoc = null;
let groupMemberDoc = null;
let memberDoc = null;

try {
  leaderDoc = userId ? await Leader.findById(userId).lean() : null;
  groupMemberDoc = (!leaderDoc && userId) ? await GroupMember.findById(userId).lean() : null;
  memberDoc = (!leaderDoc && !groupMemberDoc && userId) ? await Member.findById(userId).lean() : null;
} catch (_) { /* ignore */ }

// Build group roster: includes the leader + all group members
let myGroupAuthorIds = new Set();

if (leaderDoc) {
  myGroupAuthorIds.add(String(leaderDoc._id));
  const groupMembersForLeader = await GroupMember.find({ leaderId: leaderDoc._id }).select('_id').lean();

  if (!groupMembersForLeader.length && leaderDoc.groupName) {
    const byGroupName = await GroupMember.find({ groupName: leaderDoc.groupName }).select('_id').lean();
    byGroupName.forEach(m => myGroupAuthorIds.add(String(m._id)));
  } else {
    groupMembersForLeader.forEach(m => myGroupAuthorIds.add(String(m._id)));
  }
} else if (groupMemberDoc) {
  if (groupMemberDoc.leaderId) myGroupAuthorIds.add(String(groupMemberDoc.leaderId));
  myGroupAuthorIds.add(String(groupMemberDoc._id));

  const peers = await GroupMember.find(
    groupMemberDoc.leaderId
      ? { leaderId: groupMemberDoc.leaderId }
      : (groupMemberDoc.groupName ? { groupName: groupMemberDoc.groupName } : { _id: null })
  ).select('_id').lean();

  peers.forEach(p => myGroupAuthorIds.add(String(p._id)));
}

// Build an organization key for the current viewer
const me = leaderDoc || groupMemberDoc || memberDoc || {};
const myOrgKey =
  normalize(me.organizationId) ||
  normalize(me.organization) ||
  emailDomain(me.email);

// We’ll cache author org keys so we don’t keep hitting the DB
const authorOrgKeyCache = new Map();

async function getAuthorOrgKey(authorId) {
  const key = String(authorId);
  if (authorOrgKeyCache.has(key)) return authorOrgKeyCache.get(key);

  let aLeader = null, aGM = null, aMember = null;
  try {
    aLeader = await Leader.findById(authorId).select('organizationId organization email').lean();
    if (!aLeader) aGM = await GroupMember.findById(authorId).select('organizationId organization email').lean();
    if (!aLeader && !aGM) aMember = await Member.findById(authorId).select('organizationId organization email').lean();
  } catch (_) { /* ignore */ }

  const doc = aLeader || aGM || aMember || {};
  const orgKey =
    normalize(doc.organizationId) ||
    normalize(doc.organization) ||
    emailDomain(doc.email) ||
    null;

  authorOrgKeyCache.set(key, orgKey);
  return orgKey;
}

// 1) My units (authored by me)
const myLibraryUnits = libraryUnits.filter(u => userId && String(u.authorId) === String(userId));

// 2) My group's units = authored by anyone in my group roster (Leader + members)
const groupLibraryUnits = libraryUnits.filter(u => myGroupAuthorIds.has(String(u.authorId)));

// 3) My organization's units = authored by anyone whose org matches mine,
//    and whose visibility allows org/community viewing (exclude team_only)
let orgLibraryUnits = [];
if (myOrgKey) {
  const uniqAuthorIds = [...new Set(libraryUnits.map(u => String(u.authorId)).filter(Boolean))];
  const orgKeyMap = new Map();
  for (const aid of uniqAuthorIds) {
    orgKeyMap.set(aid, await getAuthorOrgKey(aid));
  }
  orgLibraryUnits = libraryUnits.filter(u => {
    const vis = u.visibility || 'all_members';
    if (!['organization_only', 'all_members'].includes(vis)) return false;
    const authorOrgKey = orgKeyMap.get(String(u.authorId));
    return !!authorOrgKey && authorOrgKey === myOrgKey;
  });
} else {
  orgLibraryUnits = libraryUnits.filter(u => u.visibility === 'organization_only');
}

// 4) Twennie’s units = globally visible (all_members)
//    (These can ALSO appear in group/org sections; duplication across sections is OK)
const twennieLibraryUnits = libraryUnits.filter(u => (u.visibility || 'all_members') === 'all_members');
//
// ---- END: smarter segmentation by authorship + visibility ----






// 👇 Make sure this comes BEFORE you use `user` in logic
const user = req.user; // NOT req.session.user

const loggedIn = !!user;
const accessLevel = user?.accessLevel || null;
const membershipType = user?.membershipType || null;

const injectAccessData = (units) =>
  units.map(unit => ({
    ...unit,
    loggedIn,
    isLeaderOrGroupMember:
      membershipType === "leader" || membershipType === "group_member",
    isPaid:
      membershipType === "member" &&
      (accessLevel === "paid_individual" || accessLevel === "contributor_individual"),
    isFree: membershipType === "member" && accessLevel === "free_individual",
    isVideoOrArticle: unit.type === "video" || unit.type === "article"
  }));

const sectionedUnits = [
  {
    sectionTitle: "my library units",
    units: injectAccessData(myLibraryUnits),
    emptyMessage: "If you'd like to contribute new units to the library, go to your dashboard under the \"contribute to the library\" tab. Complete the form for your unit, which could be an article, video, interview, prompt set, template or exercise. Choose up to two topics for each unit. Your contributions will show here under \"my library units\"."
  },
  {
    sectionTitle: "my group's library units",
    units: injectAccessData(groupLibraryUnits),
    emptyMessage: "If you'd like to see your group contributing units to the library, encourage them to explore Twennie's topics and find ones they feel confident talking about. They can share within your group only, your organization only, or with the whole Twennie community."
  },
  {
    sectionTitle: "my organization's library units",
    units: injectAccessData(orgLibraryUnits),
    emptyMessage: "Organizations with a culture of learning are stronger and more successful. If you'd like to see your organization contributing units to the library, start by contributing yourself. Write articles and record videos on topics that interest you. If you have templates and exercises that have been useful to you in the past, share those, too. Your organization will follow your lead."
  },
  {
    sectionTitle: "Twennie's library units",
    units: injectAccessData(twennieLibraryUnits),
    emptyMessage: "Twennie is continually adding new units to the library. This topic will have units added in the near future. Check back with us soon!"
  }
];

res.render('bytopic_views/bytopic_view', {
  layout: 'bytopiclayout',
  title: topic.title,
  shortSummary: topic.shortSummary,
  longSummary: topic.longSummary,
  sectionedUnits
});



    } catch (error) {
        console.error('Error loading topic or units:', error);
        return res.status(500).send('An internal error occurred.');
    }
};

exports.showTopicSuggestionForm = async (req, res) => {
    const { user } = req.session;

    try {
        let memberData;
        let memberType;

        if (!user) {
            return res.status(401).send('You must be logged in to suggest a topic.');
        }

        if (await Leader.findById(user.id)) {
            memberData = await Leader.findById(user.id).select('groupLeaderName email groupName');
            memberType = 'Leader';
        } else if (await GroupMember.findById(user.id)) {
            memberData = await GroupMember.findById(user.id).select('name email groupName');
            memberType = 'GroupMember';
        } else {
            memberData = await Member.findById(user.id).select('name email');
            memberType = 'Member';
        }

        res.render('bytopic_views/suggest_topic_form', {
            layout: 'mainlayout',
            csrfToken: req.csrfToken(),
            user: {
                name: memberData.groupLeaderName || memberData.name,
                email: memberData.email,
                groupName: memberData.groupName || null,
                memberType,
                memberId: user.id
            }
        });
    } catch (error) {
        console.error('Error loading suggest topic form:', error);
        res.status(500).send('Could not load form.');
    }
};

exports.submitTopicSuggestion = async (req, res) => {
    const { name, email, groupName, topicTitle, paragraph1, paragraph2, paragraph3 } = req.body;
    const { user } = req.session;

    if (!user) {
        return res.status(401).send('You must be logged in to submit a topic.');
    }

    try {
        let memberType = 'Member';
        if (await Leader.findById(user.id)) memberType = 'Leader';
        else if (await GroupMember.findById(user.id)) memberType = 'GroupMember';

        const suggestion = new TopicSuggestion({
            suggestedBy: user.id,
            memberType,
            name,
            email,
            groupName,
            topicTitle,
            paragraph1,
            paragraph2,
            paragraph3
        });

        await suggestion.save();

        res.render('bytopic_views/topic_suggestion_success', {
            layout: 'mainlayout',
            title: 'Thank you!',
            message: 'Your topic suggestion has been submitted successfully.'
        });
    } catch (error) {
        console.error('Error submitting topic suggestion:', error);
        res.status(500).send('There was an error submitting your suggestion.');
    }
};






















