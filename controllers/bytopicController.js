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
const OrganizationProfile = require('../models/profile_models/organization_profile');




// Resolves an author's display name and profile image based on their role.
// Leaders, Group Members, and Members are stored in separate models by design.
// Leaders use `groupLeaderName` instead of `name`, so we map it manually here for consistency.

async function resolveAuthorById(authorId) {
  try {
    let profile = await LeaderProfile.findOne({ leaderId: authorId })
      .select('profileImage name')
      .lean();

    if (profile) {
      return {
        name: profile.name || 'Leader',
        image: profile.profileImage || '/images/default-avatar.png'
      };
    }

    profile = await GroupMemberProfile.findOne({ groupMemberId: authorId })
      .select('profileImage name')
      .lean();

    if (profile) {
      return {
        name: profile.name || 'Group Member',
        image: profile.profileImage || '/images/default-avatar.png'
      };
    }

    profile = await MemberProfile.findOne({ memberId: authorId })
      .select('profileImage name')
      .lean();

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

async function resolveAuthorAndOrgById(authorId) {
  const author = await resolveAuthorById(authorId);

  let organizationId = null;
  let organizationName = '';
  let organizationLogo = '/images/default-organization-logo.png';

  try {
    let leader = await Leader.findById(authorId)
      .select('organization organizationName groupName email')
      .lean();

    if (leader) {
      organizationId = leader.organization || null;
      organizationName = leader.organizationName || '';
    } else {
      let groupMember = await GroupMember.findById(authorId)
        .select('organization organizationName groupId leader groupName email')
        .lean();

      if (groupMember) {
        organizationId = groupMember.organization || null;
        organizationName = groupMember.organizationName || '';

        // Fallback 1: inherit from linked leader/group id
        if (!organizationId && (groupMember.leader || groupMember.groupId)) {
          const parentLeader = await Leader.findById(groupMember.leader || groupMember.groupId)
            .select('organization organizationName groupName email')
            .lean();

          if (parentLeader) {
            organizationId = parentLeader.organization || null;
            organizationName = parentLeader.organizationName || '';
          }
        }

        // Fallback 2: inherit from leader by matching groupName
        if (!organizationId && groupMember.groupName) {
          const parentLeaderByGroupName = await Leader.findOne({ groupName: groupMember.groupName })
            .select('organization organizationName groupName email')
            .lean();

          if (parentLeaderByGroupName) {
            organizationId = parentLeaderByGroupName.organization || null;
            organizationName = parentLeaderByGroupName.organizationName || '';
          }
        }
      } else {
        const member = await Member.findById(authorId)
          .select('organization organizationName email')
          .lean();

        if (member) {
          organizationId = member.organization || null;
          organizationName = member.organizationName || '';
        }
      }
    }

    if (organizationId) {
      const orgProfile = await OrganizationProfile.findOne({ organizationId })
        .select('logo')
        .lean();

      if (orgProfile?.logo?.url) {
        organizationLogo = orgProfile.logo.url;
      }
    }
  } catch (error) {
    console.error('Error resolving organization for author:', error);
  }

  return {
    ...author,
    organizationId,
    organizationName,
    organizationLogo
  };
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



const originalTopicTitle = topicsData.topics.find(
  (t) => t.title.toLowerCase().replace(/[^a-z0-9]/g, '') === normalizedTopic
)?.title;

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
  ? await resolveAuthorAndOrgById(authorId)
  : {
      name: 'Unknown Author',
      image: '/images/default-avatar.png',
      organizationId: null,
      organizationName: '',
      organizationLogo: '/images/default-organization-logo.png'
    };

return {
  ...unit,
  authorName: author.name,
  authorImage: author.image || '/images/default-avatar.png',
  organizationId: author.organizationId,
  organizationName: author.organizationName,
  organizationLogo: author.organizationLogo
};
  })
);

//
// ---- BEGIN: smarter segmentation by authorship + visibility ----
const userId = (req.user?._id || req.user?.id)?.toString() || null;

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

  const [groupMembersForLeader, byGroupName] = await Promise.all([
    GroupMember.find({ leader: leaderDoc._id }).select('_id').lean(),
    leaderDoc.groupName
      ? GroupMember.find({ groupName: leaderDoc.groupName }).select('_id').lean()
      : Promise.resolve([])
  ]);

  groupMembersForLeader.forEach(m => myGroupAuthorIds.add(String(m._id)));
  byGroupName.forEach(m => myGroupAuthorIds.add(String(m._id)));

} else if (groupMemberDoc) {
  const leaderId = groupMemberDoc.leader || groupMemberDoc.groupId || null;

  if (leaderId) myGroupAuthorIds.add(String(leaderId));
  myGroupAuthorIds.add(String(groupMemberDoc._id));

  const [peersByLeader, peersByGroupName] = await Promise.all([
    leaderId
      ? GroupMember.find({
          $or: [
            { leader: leaderId },
            { groupId: leaderId }
          ]
        }).select('_id').lean()
      : Promise.resolve([]),
    groupMemberDoc.groupName
      ? GroupMember.find({ groupName: groupMemberDoc.groupName }).select('_id').lean()
      : Promise.resolve([])
  ]);

  peersByLeader.forEach(p => myGroupAuthorIds.add(String(p._id)));
  peersByGroupName.forEach(p => myGroupAuthorIds.add(String(p._id)));
}

console.log('leaderDoc:', leaderDoc ? {
  _id: String(leaderDoc._id),
  groupName: leaderDoc.groupName
} : null);

console.log('groupMemberDoc:', groupMemberDoc ? {
  _id: String(groupMemberDoc._id),
  leader: groupMemberDoc.leader ? String(groupMemberDoc.leader) : null,
  groupName: groupMemberDoc.groupName
} : null);

console.log('myGroupAuthorIds:', [...myGroupAuthorIds]);

// Build an organization key for the current viewer
const me = leaderDoc || groupMemberDoc || memberDoc || {};

let myOrgKey =
  me.organization ? String(me.organization) :
  normalize(me.organizationId) ||
  normalize(me.organizationName) ||
  null;

// If viewer is a group member with no direct org, inherit from leader/group
if (!myOrgKey && groupMemberDoc) {
  const leaderId = groupMemberDoc.leader || groupMemberDoc.groupId || null;

  if (leaderId) {
    const parentLeader = await Leader.findById(leaderId)
      .select('organization organizationId organizationName email')
      .lean();

    if (parentLeader) {
      myOrgKey =
        (parentLeader.organization ? String(parentLeader.organization) : null) ||
        normalize(parentLeader.organizationId) ||
        normalize(parentLeader.organizationName) ||
        null;
    }
  }

  // extra fallback: match by groupName
  if (!myOrgKey && groupMemberDoc.groupName) {
    const parentLeaderByGroupName = await Leader.findOne({ groupName: groupMemberDoc.groupName })
      .select('organization organizationId organizationName email')
      .lean();

    if (parentLeaderByGroupName) {
      myOrgKey =
        (parentLeaderByGroupName.organization ? String(parentLeaderByGroupName.organization) : null) ||
        normalize(parentLeaderByGroupName.organizationId) ||
        normalize(parentLeaderByGroupName.organizationName) ||
        null;
    }
  }
}

// absolute last resort only
if (!myOrgKey) {
  myOrgKey = emailDomain(me.email);
}

// We’ll cache author org keys so we don’t keep hitting the DB
const authorOrgKeyCache = new Map();

async function getAuthorOrgKey(authorId) {
  const key = String(authorId);
  if (authorOrgKeyCache.has(key)) return authorOrgKeyCache.get(key);

  let aLeader = null;
  let aGM = null;
  let aMember = null;

  try {
    aLeader = await Leader.findById(authorId)
      .select('organizationId organization organizationName email groupName')
      .lean();

    if (!aLeader) {
      aGM = await GroupMember.findById(authorId)
        .select('organizationId organization organizationName email groupId leader groupName')
        .lean();
    }

    if (!aLeader && !aGM) {
      aMember = await Member.findById(authorId)
        .select('organizationId organization organizationName email')
        .lean();
    }
  } catch (_) { /* ignore */ }

  const doc = aLeader || aGM || aMember || {};

  // STEP 1: use explicit org fields only
  let orgKey =
    normalize(doc.organization) ||
    normalize(doc.organizationId) ||
    normalize(doc.organizationName) ||
    null;

  // STEP 2: if group member has no org fields, inherit from leader/group
  if (!orgKey && aGM) {
    try {
      const gmLeaderId = aGM.leader || aGM.groupId || null;

      if (gmLeaderId) {
        const parentLeader = await Leader.findById(gmLeaderId)
          .select('organizationId organization organizationName email groupName')
          .lean();

        if (parentLeader) {
          orgKey =
            normalize(parentLeader.organization) ||
            normalize(parentLeader.organizationId) ||
            normalize(parentLeader.organizationName) ||
            null;
        }
      }

      // optional extra fallback: match by groupName if needed
      if (!orgKey && aGM.groupName) {
        const parentLeaderByGroupName = await Leader.findOne({ groupName: aGM.groupName })
          .select('organizationId organization organizationName email groupName')
          .lean();

        if (parentLeaderByGroupName) {
          orgKey =
            normalize(parentLeaderByGroupName.organization) ||
            normalize(parentLeaderByGroupName.organizationId) ||
            normalize(parentLeaderByGroupName.organizationName) ||
            null;
        }
      }
    } catch (_) { /* ignore */ }
  }

  // STEP 3: optional final fallback to email domain
  if (!orgKey) {
    orgKey = emailDomain(doc.email) || null;
  }

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
    // 🔍 DEBUG LOGS — PUT THEM HERE
  console.log('myOrgKey:', myOrgKey);
  console.log('orgKeyMap:', Object.fromEntries(orgKeyMap));

  console.log('org unit check:', libraryUnits.map(u => ({
    title: u.title,
    authorId: String(u.authorId),
    visibility: u.visibility,
    orgKey: orgKeyMap.get(String(u.authorId))
  })));

  orgLibraryUnits = libraryUnits.filter(u => {
    const vis = u.visibility || 'all_members';
    if (!['organization_only', 'all_members'].includes(vis)) return false;
    const authorOrgKey = orgKeyMap.get(String(u.authorId));
    return !!authorOrgKey && authorOrgKey === myOrgKey;
  });
} else {
  orgLibraryUnits = [];
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

const seenUnitIds = new Set();

const dedupedSectionedUnits = sectionedUnits.map(section => {
  const dedupedUnits = section.units.filter(unit => {
    const uniqueKey = unit._id
      ? String(unit._id)
      : `${unit.type}:${unit.title}:${unit.authorId || 'no-author'}`;

    if (seenUnitIds.has(uniqueKey)) return false;
    seenUnitIds.add(uniqueKey);
    return true;
  });

  return {
    ...section,
    units: dedupedUnits
  };
});

res.render('bytopic_views/bytopic_view', {
  layout: 'bytopiclayout',
  title: topic.title,
  shortSummary: topic.shortSummary,
  longSummary: topic.longSummary,
  sectionedUnits: dedupedSectionedUnits
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






















