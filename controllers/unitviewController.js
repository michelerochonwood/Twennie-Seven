const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview'); // Import Interview model
const PromptSet = require('../models/unit_models/promptset');
const Template = require('../models/unit_models/template');
const Exercise = require('../models/unit_models/exercise');
const Mission = require('../models/unit_models/mission'); // ✅ ADD THIS

const Leader = require('../models/member_models/leader'); // Import Leader model
const GroupMember = require('../models/member_models/group_member'); // Import Group Member model
const Member = require('../models/member_models/member');
const mongoose = require('mongoose');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const MemberProfile = require('../models/profile_models/member_profile');
const sanitizeHtml = require('sanitize-html');
const UpcomingUnit = require('../models/unit_models/upcoming'); // models/unit_models/upcoming.js
const Nugget = require('../models/unit_models/nugget'); // add this at the top with other models
const OrganizationProfile = require('../models/profile_models/organization_profile');

function isPaidMember(req) {
  const t = req.user?.accessLevel || req.user?.membershipType;
  return ['paid_individual', 'leader', 'group_member'].includes(t);
}

// Add this helper at the top of the controller file (outside the viewInterview function)
function convertYouTubeToEmbed(url) {
  if (!url) return null;

  // Match typical YouTube formats like:
  // - https://www.youtube.com/watch?v=VIDEO_ID
  // - https://youtu.be/VIDEO_ID
  // - https://www.youtube.com/embed/VIDEO_ID
  const match = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)([\w-]{11})/);

  return match ? `https://www.youtube.com/embed/${match[1]}` : null;
}

function dedupeSectionedNuggets(sectionedNuggets) {
  const seenNuggetIds = new Set();

  return sectionedNuggets.map(section => {
    const dedupedNuggets = (section.nuggets || []).filter(nugget => {
      const uniqueKey = nugget._id
        ? String(nugget._id)
        : `${nugget.title || 'untitled'}:${nugget.createdBy || 'no-creator'}`;

      if (seenNuggetIds.has(uniqueKey)) return false;
      seenNuggetIds.add(uniqueKey);
      return true;
    });

    return {
      ...section,
      nuggets: dedupedNuggets
    };
  });
}

async function resolveAuthorById(authorId) {
  if (!authorId) {
    return {
      name: 'Unknown Author',
      image: '/images/default-avatar.png',
      organization: null,
      groupId: null
    };
  }

  const idStr = authorId.toString();

  // 1) Leader profile
  let profile = await LeaderProfile
    .findOne({ leaderId: idStr })
    .select('profileImage name organization')
    .lean();

  if (profile) {
    // Leaders anchor their own "group" using their Leader _id
    const leader = await Leader.findById(idStr).select('_id groupName organization').lean();

    return {
      name: (profile.name || leader?.groupLeaderName || leader?.username || 'Leader'),
      image: profile.profileImage || '/images/default-avatar.png',
      organization: profile.organization || leader?.organization || null,
      groupId: leader?._id || null
    };
  }

  // 2) Group member profile
profile = await GroupMemberProfile
  .findOne({ groupMemberId: idStr })
  .select('profileImage name')
  .lean();

if (profile) {
  const gm = await GroupMember.findById(idStr).select('_id organization leader').lean();

  return {
    name: profile.name || 'Group Member',
    image: profile.profileImage || '/images/default-avatar.png',
    organization: gm?.organization || null,
    groupId: gm?.leader || null // keep the property name "groupId" if other code expects it
  };
}


  // 3) Individual member profile
  profile = await MemberProfile
    .findOne({ memberId: idStr })
    .select('profileImage name')
    .lean();

  if (profile) {
    const member = await Member.findById(idStr).select('_id organization').lean();

    return {
      name: profile.name || 'Member',
      image: profile.profileImage || '/images/default-avatar.png',
      organization: member?.organization || null,
      groupId: null
    };
  }

  // 4) Fallback (no profiles found)
  return {
    name: 'Unknown Author',
    image: '/images/default-avatar.png',
    organization: null,
    groupId: null
  };
}

async function resolveCreatorAndOrgById(authorId) {
  const creator = await resolveAuthorById(authorId);

  let organizationId = null;
  let organizationName = '';
  let organizationLogo = '/images/default-organization-logo.png';

  try {
    let leader = await Leader.findById(authorId)
      .select('organization organizationName email groupName')
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

        if (!organizationId && (groupMember.leader || groupMember.groupId)) {
          const parentLeader = await Leader.findById(groupMember.leader || groupMember.groupId)
            .select('organization organizationName email groupName')
            .lean();

          if (parentLeader) {
            organizationId = parentLeader.organization || null;
            organizationName = parentLeader.organizationName || '';
          }
        }

        if (!organizationId && groupMember.groupName) {
          const parentLeaderByGroupName = await Leader.findOne({ groupName: groupMember.groupName })
            .select('organization organizationName email groupName')
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
    console.error('Error resolving organization for nugget creator:', error);
  }

  return {
    ...creator,
    organizationId,
    organizationName,
    organizationLogo
  };
}

async function enrichNuggetsForCards(nuggets, req) {
  const user = req.user || null;
  const loggedIn = !!user;
  const membershipType = user?.membershipType || null;
  const accessLevel = user?.accessLevel || null;

  const isLeaderOrGroupMember =
    membershipType === 'leader' || membershipType === 'group_member';

  const isPaid =
    isLeaderOrGroupMember ||
    (membershipType === 'member' &&
      (accessLevel === 'paid_individual' || accessLevel === 'contributor_individual'));

  const isFree =
    membershipType === 'member' && accessLevel === 'free_individual';

  const creatorCache = new Map();

  async function getCreatorMeta(createdBy) {
    const key = String(createdBy || '');
    if (!key) {
      return {
        name: 'Unknown Author',
        image: '/images/default-avatar.png',
        organizationId: null,
        organizationName: '',
        organizationLogo: '/images/default-organization-logo.png'
      };
    }

    if (creatorCache.has(key)) return creatorCache.get(key);

    const meta = await resolveCreatorAndOrgById(key);
    creatorCache.set(key, meta);
    return meta;
  }

  const enriched = [];

  for (const nugget of nuggets) {
    const createdBy = nugget.createdBy?.toString?.() || String(nugget.createdBy || '');
    const creatorMeta = await getCreatorMeta(createdBy);

    enriched.push({
      ...nugget,
      creatorName: creatorMeta.name || 'Unknown Author',
      creatorImage: creatorMeta.image || '/images/default-avatar.png',
      organizationId: creatorMeta.organizationId || null,
      organizationName: creatorMeta.organizationName || '',
      organizationLogo: creatorMeta.organizationLogo || '/images/default-organization-logo.png',

      loggedIn,
      isLeaderOrGroupMember,
      isPaid,
      isFree
    });
  }

  return enriched;
}

async function buildOrgLeaderListForAdmin(req) {
  const userId = req.user?._id || req.user?.id;
  if (!userId) return { isOrgAdmin: false, orgLeaders: [] };

  const admin = await Leader.findById(userId)
    .select('organization organizationOptOut isAdmin')
    .lean();

  if (!admin?.isAdmin) return { isOrgAdmin: false, orgLeaders: [] };
  if (!admin?.organization || admin.organizationOptOut === true) {
    return { isOrgAdmin: false, orgLeaders: [] };
  }

  const orgId = admin.organization;

  const orgLeaders = await Leader.find({
    organization: orgId,
    organizationOptOut: { $ne: true },
    _id: { $ne: admin._id }
  })
    .select('_id groupLeaderName groupName')
    .sort({ groupName: 1 })
    .lean();

  return { isOrgAdmin: true, orgLeaders };
}

// Unified leader assign context for ALL unit views
async function getLeaderAssignContext(req) {
  const currentUserId = (req.user?._id || req.user?.id)?.toString();
  const isLeader = req.user?.membershipType === 'leader';

  let groupMembers = [];
  let leaderId = null;
  let leaderName = null;

  if (isLeader && currentUserId) {
    const leaderDoc = await Leader.findById(currentUserId)
      .select('_id groupLeaderName username')
      .lean();

    if (leaderDoc) {
      leaderId = leaderDoc._id.toString();
      leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';

      // ✅ schema is leader; support legacy groupId just in case
      groupMembers = await GroupMember.find({
        $or: [{ leader: leaderDoc._id }, { groupId: leaderDoc._id }]
      })
        .select('_id name')
        .lean();
    }
  }

  return { isLeader, groupMembers, leaderId, leaderName };
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

async function getAuthorOrgTeam(authorId) {
  if (!authorId) return { authorOrg: null, authorTeamId: null };

  const idStr = authorId.toString();

  const [asLeader, asGroupMember] = await Promise.all([
    Leader.findById(idStr).select('_id organization').lean(),
    GroupMember.findById(idStr).select('_id organization leader').lean()
  ]);

  if (asLeader) {
    return {
      authorOrg: asLeader.organization || null,
      authorTeamId: asLeader._id || null
    };
  }

  if (asGroupMember) {
    return {
      authorOrg: asGroupMember.organization || null,
      authorTeamId: asGroupMember.leader || null
    };
  }

  // Individuals: only org string sometimes; treat as no team anchor
  const asMember = await Member.findById(idStr).select('_id organization').lean();
  return {
    authorOrg: asMember?.organization || null,
    authorTeamId: null
  };
}

module.exports = {


// ---- The Mine: Clients view (requires createdBy on every nugget) ----
viewMineClients: async (req, res) => {
  try {
    console.log('[viewMineClients] start, user:', req.user?.id || req.user?._id);

    if (!isPaidMember(req)) {
      console.log('[viewMineClients] blocked: not paid member');
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'The Mine is available to paid members only.',
      });
    }

    const nuggets = await Nugget.find({
      client: { $exists: true, $ne: '' },
      createdBy: { $exists: true, $ne: null },
    })
      .sort({ client: 1 })
      .lean();

    console.log('[viewMineClients] nuggets count (client & createdBy):', nuggets.length);

    const meId = (req.user?._id || req.user?.id || '').toString();

    let myGroupId = null;
    let myOrg = null;

    if (meId) {
      const [meAsLeader, meAsGroupMember, meAsMember] = await Promise.all([
        Leader.findById(meId).select('_id organization').lean(),
        GroupMember.findById(meId).select('_id organization leader').lean(),
        Member.findById(meId).select('_id organization').lean(),
      ]);

      if (meAsLeader) {
        myGroupId = meAsLeader._id?.toString() || null;
        myOrg = meAsLeader.organization || null;
      } else if (meAsGroupMember) {
        myGroupId = meAsGroupMember.leader ? meAsGroupMember.leader.toString() : null;
        myOrg = meAsGroupMember.organization || null;
      } else if (meAsMember) {
        myOrg = meAsMember.organization || null;
      }
    }

    const creatorIds = [...new Set(nuggets.map(n => n.createdBy?.toString()).filter(Boolean))];
    const orgByCreator = Object.create(null);
    const groupByCreator = Object.create(null);

    if (creatorIds.length) {
      const [leaders, groupMembers] = await Promise.all([
        Leader.find({ _id: { $in: creatorIds } }).select('_id organization').lean(),
        GroupMember.find({ _id: { $in: creatorIds } }).select('_id organization leader').lean(),
      ]);

      leaders.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = doc._id.toString();
      });

      groupMembers.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = (doc.leader && doc.leader.toString()) || groupByCreator[id] || null;
      });
    }

    const createdByMeRaw = meId ? nuggets.filter(n => n.createdBy?.toString() === meId) : [];
    const createdByMyGroupRaw = myGroupId
      ? nuggets.filter(n => groupByCreator[n.createdBy?.toString()] === myGroupId)
      : [];
    const createdByMyOrgRaw = myOrg
      ? nuggets.filter(n => orgByCreator[n.createdBy?.toString()] === myOrg)
      : [];
    const fromAllMembersRaw = nuggets;

    const [
      createdByMe,
      createdByMyGroup,
      createdByMyOrg,
      fromAllMembers
    ] = await Promise.all([
      enrichNuggetsForCards(createdByMeRaw, req),
      enrichNuggetsForCards(createdByMyGroupRaw, req),
      enrichNuggetsForCards(createdByMyOrgRaw, req),
      enrichNuggetsForCards(fromAllMembersRaw, req),
    ]);

    const sectionedNuggets = dedupeSectionedNuggets([
      { sectionTitle: 'Created by Me', nuggets: createdByMe, emptyMessage: 'No client nuggets created by you yet.' },
      { sectionTitle: 'Created by My Group', nuggets: createdByMyGroup, emptyMessage: 'No client nuggets from your group yet.' },
      { sectionTitle: 'Created by My Organization', nuggets: createdByMyOrg, emptyMessage: 'No client nuggets from your organization yet.' },
      { sectionTitle: 'From All Members', nuggets: fromAllMembers, emptyMessage: 'No client nuggets available.' },
    ]);

    return res.render('unit_views/client_view', {
      layout: 'unitviewlayout',
      pageTitle: 'Nuggets by Client',
      pageIntro: 'Open any client card to see details and jump to the full Nugget.',
      sectionedNuggets,
    });
  } catch (err) {
    console.error('viewMineClients error:', err);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'Unable to load client Nuggets.',
    });
  }
},







// ---- The Mine: Regions list ----
// ---- The Mine: Regions list (cards like client_view, title = region) ----
viewMineRegions: async (req, res) => {
  try {
    console.log('[viewMineRegions] start, user:', req.user?.id || req.user?._id);

    if (!isPaidMember(req)) {
      console.log('[viewMineRegions] blocked: not paid member');
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'The Mine is available to paid members only.',
      });
    }

    const nuggets = await Nugget.find({
      region: { $exists: true, $ne: '' },
      createdBy: { $exists: true, $ne: null },
    })
      .sort({ region: 1 })
      .lean();

    console.log('[viewMineRegions] nuggets count (region & createdBy):', nuggets.length);

    const meId = (req.user?._id || req.user?.id || '').toString();

    let myGroupId = null;
    let myOrg = null;

    if (meId) {
      const [meAsLeader, meAsGroupMember, meAsMember] = await Promise.all([
        Leader.findById(meId).select('_id organization').lean(),
        GroupMember.findById(meId).select('_id organization leader').lean(),
        Member.findById(meId).select('_id organization').lean(),
      ]);

      if (meAsLeader) {
        myGroupId = meAsLeader._id?.toString() || null;
        myOrg = meAsLeader.organization || null;
      } else if (meAsGroupMember) {
        myGroupId = meAsGroupMember.leader ? meAsGroupMember.leader.toString() : null;
        myOrg = meAsGroupMember.organization || null;
      } else if (meAsMember) {
        myOrg = meAsMember.organization || null;
      }
    }

    const creatorIds = [...new Set(nuggets.map(n => n.createdBy?.toString()).filter(Boolean))];
    const orgByCreator = Object.create(null);
    const groupByCreator = Object.create(null);

    if (creatorIds.length) {
      const [leaders, groupMembers] = await Promise.all([
        Leader.find({ _id: { $in: creatorIds } }).select('_id organization').lean(),
        GroupMember.find({ _id: { $in: creatorIds } }).select('_id organization leader').lean(),
      ]);

      leaders.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = id;
      });

      groupMembers.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = (doc.leader && doc.leader.toString()) || groupByCreator[id] || null;
      });
    }

    const createdByMeRaw = meId ? nuggets.filter(n => n.createdBy?.toString() === meId) : [];
    const createdByMyGroupRaw = myGroupId
      ? nuggets.filter(n => groupByCreator[n.createdBy?.toString()] === myGroupId)
      : [];
    const createdByMyOrgRaw = myOrg
      ? nuggets.filter(n => orgByCreator[n.createdBy?.toString()] === myOrg)
      : [];
    const fromAllMembersRaw = nuggets;

    const [
      createdByMe,
      createdByMyGroup,
      createdByMyOrg,
      fromAllMembers
    ] = await Promise.all([
      enrichNuggetsForCards(createdByMeRaw, req),
      enrichNuggetsForCards(createdByMyGroupRaw, req),
      enrichNuggetsForCards(createdByMyOrgRaw, req),
      enrichNuggetsForCards(fromAllMembersRaw, req),
    ]);

    const sectionedNuggets = dedupeSectionedNuggets([
      { sectionTitle: 'Created by Me', nuggets: createdByMe, emptyMessage: 'No region nuggets created by you yet.' },
      { sectionTitle: 'Created by My Group', nuggets: createdByMyGroup, emptyMessage: 'No region nuggets from your group yet.' },
      { sectionTitle: 'Created by My Organization', nuggets: createdByMyOrg, emptyMessage: 'No region nuggets from your organization yet.' },
      { sectionTitle: 'From All Members', nuggets: fromAllMembers, emptyMessage: 'No region nuggets available.' },
    ]);

    return res.render('unit_views/region_view', {
      layout: 'unitviewlayout',
      pageTitle: 'Nuggets by Region',
      pageIntro: 'Open any region card to see details and jump to the full Nugget.',
      sectionedNuggets,
    });
  } catch (err) {
    console.error('viewMineRegions error:', err);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'Unable to load region Nuggets.',
    });
  }
},



// ---- The Mine: Disciplines list ----
// ---- The Mine: Disciplines list (cards like client_view, title = discipline) ----
viewMineDisciplines: async (req, res) => {
  try {
    console.log('[viewMineDisciplines] start, user:', req.user?.id || req.user?._id);

    if (!isPaidMember(req)) {
      console.log('[viewMineDisciplines] blocked: not paid member');
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'The Mine is available to paid members only.',
      });
    }

    const nuggets = await Nugget.find({
      discipline: { $exists: true, $ne: '' },
      createdBy: { $exists: true, $ne: null },
    })
      .sort({ discipline: 1 })
      .lean();

    console.log('[viewMineDisciplines] nuggets count (discipline & createdBy):', nuggets.length);

    const meId = (req.user?._id || req.user?.id || '').toString();

    let myGroupId = null;
    let myOrg = null;

    if (meId) {
      const [meAsLeader, meAsGroupMember, meAsMember] = await Promise.all([
        Leader.findById(meId).select('_id organization').lean(),
        GroupMember.findById(meId).select('_id organization leader').lean(),
        Member.findById(meId).select('_id organization').lean(),
      ]);

      if (meAsLeader) {
        myGroupId = meAsLeader._id?.toString() || null;
        myOrg = meAsLeader.organization || null;
      } else if (meAsGroupMember) {
        myGroupId = meAsGroupMember.leader ? meAsGroupMember.leader.toString() : null;
        myOrg = meAsGroupMember.organization || null;
      } else if (meAsMember) {
        myOrg = meAsMember.organization || null;
      }
    }

    const creatorIds = [...new Set(nuggets.map(n => n.createdBy?.toString()).filter(Boolean))];
    const orgByCreator = Object.create(null);
    const groupByCreator = Object.create(null);

    if (creatorIds.length) {
      const [leaders, groupMembers] = await Promise.all([
        Leader.find({ _id: { $in: creatorIds } }).select('_id organization').lean(),
        GroupMember.find({ _id: { $in: creatorIds } }).select('_id organization leader').lean(),
      ]);

      leaders.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = id;
      });

      groupMembers.forEach(doc => {
        const id = doc._id.toString();
        orgByCreator[id] = doc.organization || orgByCreator[id] || null;
        groupByCreator[id] = (doc.leader && doc.leader.toString()) || groupByCreator[id] || null;
      });
    }

    const createdByMeRaw = meId ? nuggets.filter(n => n.createdBy?.toString() === meId) : [];
    const createdByMyGroupRaw = myGroupId
      ? nuggets.filter(n => groupByCreator[n.createdBy?.toString()] === myGroupId)
      : [];
    const createdByMyOrgRaw = myOrg
      ? nuggets.filter(n => orgByCreator[n.createdBy?.toString()] === myOrg)
      : [];
    const fromAllMembersRaw = nuggets;

    const [
      createdByMe,
      createdByMyGroup,
      createdByMyOrg,
      fromAllMembers
    ] = await Promise.all([
      enrichNuggetsForCards(createdByMeRaw, req),
      enrichNuggetsForCards(createdByMyGroupRaw, req),
      enrichNuggetsForCards(createdByMyOrgRaw, req),
      enrichNuggetsForCards(fromAllMembersRaw, req),
    ]);

    const sectionedNuggets = dedupeSectionedNuggets([
      { sectionTitle: 'Created by Me', nuggets: createdByMe, emptyMessage: 'No region nuggets created by you yet.' },
      { sectionTitle: 'Created by My Group', nuggets: createdByMyGroup, emptyMessage: 'No region nuggets from your group yet.' },
      { sectionTitle: 'Created by My Organization', nuggets: createdByMyOrg, emptyMessage: 'No region nuggets from your organization yet.' },
      { sectionTitle: 'From All Members', nuggets: fromAllMembers, emptyMessage: 'No region nuggets available.' },
    ]);

    return res.render('unit_views/discipline_view', {
      layout: 'unitviewlayout',
      pageTitle: 'Nuggets by Discipline',
      pageIntro: 'Open any discipline card to see details and jump to the full Nugget.',
      sectionedNuggets,
    });
  } catch (err) {
    console.error('viewMineDisciplines error:', err);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'Unable to load discipline Nuggets.',
    });
  }
},




  viewNugget: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`💎 Fetching nugget with ID: ${id}`);

    // 1) Fetch the nugget
    const nugget = await Nugget.findById(id);
    if (!nugget) {
      console.warn(`❌ Nugget with ID ${id} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Nugget Not Found',
        errorMessage: `The nugget with ID ${id} does not exist.`,
      });
    }

    // 2) Enforce membership: nuggets are for paying members only
    const membershipType = req.user?.accessLevel || req.user?.membershipType;
    const paidMemberships = ['paid_individual', 'leader', 'group_member'];
    if (!membershipType || !paidMemberships.includes(membershipType)) {
      console.log(`🚫 Access denied for membership type: ${membershipType}`);
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'Nuggets are only available to paid members.',
      });
    }

    // 3) Resolve creator
    const creatorId = nugget.createdBy?.toString();
    const creator = await resolveAuthorById(creatorId);

    // 4) Current user helpers
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || req.user?.accessLevel;
    const isOwner = !!(currentUserId && creatorId && currentUserId === creatorId);

    // 5) Leader assignment context (if leader)
    const isLeader = currentMembership === 'leader';
    let groupMembers = [];
    let leaderId;
    let leaderName;

    if (isLeader && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId)
        .select('_id groupLeaderName username')
        .lean();

      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 6) ✅ Org Admin suggestion context
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    // 7) Render the nugget view
    return res.render('unit_views/single_nugget', {
      layout: 'unitviewlayout',

      // Unit identity
      _id: nugget._id.toString(),
      unitType: 'nugget',

      // Core fields
      title: nugget.title,
      client: nugget.client,
      horizon: nugget.horizon,
      discipline: nugget.discipline,
      region: nugget.region,
      estimatedValue: nugget.estimatedValue,
      projectDeliveryType: nugget.projectDeliveryType,
      originalSource: nugget.originalSource,
      likelihood: nugget.likelihood,
      connectedTwennieUnits: nugget.connectedTwennieUnits || [],
      notes: nugget.notes,

      // Creator sidebar
      creator: {
        name: creator?.name || 'Unknown Author',
        image: creator?.image || '/images/default-avatar.png',
      },

      tagSuccess: req.query.tag === 'ok',

      // Flags
      isOwner,
      isAuthenticated: !!req.user,
      isLeader,
      isGroupMemberOrLeader: isLeader || currentMembership === 'group_member',
      isGroupMemberOrMember: currentMembership === 'group_member' || currentMembership === 'member',

      // ✅ Admin suggest vars (top-level)
      ...adminSuggest,

      // Leader-only assignment data
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });

  } catch (err) {
    console.error('💥 Error fetching nugget:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the nugget.',
    });
  }
},

    
viewArticle: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📄 Fetching article with ID: ${id}`);

    const article = await Article.findById(id);
    if (!article) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Article Not Found',
        errorMessage: `The article with ID ${id} does not exist.`,
      });
    }

    const authorId = (article.author?.id || article.author)?.toString();
    const author = await resolveAuthorById(authorId);

    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;

    const isLeader = currentMembership === 'leader';
    const isGroupMember = currentMembership === 'group_member';
    const isMember = currentMembership === 'member';

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    // ✅ Author org/team from real docs (team anchor = leader id)
    const { authorOrg, authorTeamId } = await getAuthorOrgTeam(authorId);

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (article.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        article.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        String(req.user.organization) === String(authorOrg);

      isTeamMatch =
        article.visibility === 'team_only' &&
        req.user?.groupId &&
        authorTeamId &&
        String(req.user.groupId) === String(authorTeamId);

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    const plainText = (article.article_body || '').replace(/<[^>]*>/g, ' ').trim();
    const wordCount = plainText ? plainText.split(/\s+/).filter(Boolean).length : 0;

    const articleImage = article.image?.url || '/images/default-article.png';

    // ✅ Leader assign + org admin suggest
    const { groupMembers, leaderId, leaderName } = await getLeaderAssignContext(req);
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    return res.render('unit_views/single_article', {
      layout: 'unitviewlayout',

      _id: article._id.toString(),
      unitType: 'article',
      article_title: article.article_title,
      short_summary: article.short_summary,
      full_summary: article.full_summary,
      article_body: article.article_body,
      article_image: articleImage,

      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      main_topic: article.main_topic,
      secondary_topics: article.secondary_topics,
      sub_topic: article.sub_topic,

      word_count: wordCount,
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,

      isLeader,
      isGroupMember,
      isMember,
      tagSuccess: req.query.tag === 'ok',

      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      ...adminSuggest,
      suggestionSuccess: req.query.suggested === '1',
      suggestedUnitId: req.query.unitId || '',
      suggestedUnitType: req.query.unitType || '',

      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });
  } catch (err) {
    console.error('💥 Error fetching article:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the article.',
    });
  }
},






      
    
   viewVideo: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🎥 Fetching video with ID: ${id}`);

    const video = await Video.findById(id);
    if (!video) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Video Not Found',
        errorMessage: `The video with ID ${id} does not exist.`,
      });
    }

    const authorId = (
      video.author?.id ||
      video.author ||
      video.createdBy ||
      video.submittedBy ||
      null
    )?.toString();

    const author = authorId
      ? await resolveAuthorById(authorId)
      : { name: 'Unknown Author', image: '/images/default-avatar.png' };

    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;

    const isLeader = currentMembership === 'leader';
    const isGroupMember = currentMembership === 'group_member';
    const isMember = currentMembership === 'member';

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    const { authorOrg, authorTeamId } = authorId
      ? await getAuthorOrgTeam(authorId)
      : { authorOrg: null, authorTeamId: null };

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (video.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        video.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        String(req.user.organization) === String(authorOrg);

      isTeamMatch =
        video.visibility === 'team_only' &&
        req.user?.groupId &&
        authorTeamId &&
        String(req.user.groupId) === String(authorTeamId);

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    const embedLink = convertYouTubeToEmbed(video.video_content);

    const { groupMembers, leaderId, leaderName } = await getLeaderAssignContext(req);
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    return res.render('unit_views/single_video', {
      layout: 'unitviewlayout',

      _id: video._id.toString(),
      unitType: 'video',
      video_title: video.video_title || video.title || 'Untitled Video',
      short_summary: video.short_summary,
      full_summary: video.full_summary,
      video_content: video.video_content || '',
      embedLink,
      video_url: video.video_url || '/images/valuegroupcont.png',

      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      main_topic: video.main_topic,
      secondary_topics: video.secondary_topics || [],
      sub_topic: video.sub_topic,

      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,

      isLeader,
      isGroupMember,
      isMember,
      tagSuccess: req.query.tag === 'ok',

      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      ...adminSuggest,
      suggestionSuccess: req.query.suggested === '1',
      suggestedUnitId: req.query.unitId || '',
      suggestedUnitType: req.query.unitType || '',

      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });
  } catch (err) {
    console.error('💥 Error fetching video:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the video.',
    });
  }
},







      
    
    
    
viewInterview: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🎙️ Fetching interview with ID: ${id}`);

    const interview = await Interview.findById(id);
    if (!interview) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Interview Not Found',
        errorMessage: `The interview with ID ${id} does not exist.`,
      });
    }

    const authorId = (interview.author?.id || interview.author)?.toString();
    const author = await resolveAuthorById(authorId);

    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;

    const isLeader = currentMembership === 'leader';
    const isGroupMember = currentMembership === 'group_member';
    const isMember = currentMembership === 'member';

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    const { authorOrg, authorTeamId } = await getAuthorOrgTeam(authorId);

    let isAuthorizedToViewFullContent = false;
    if (interview.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      const isOrgMatch =
        interview.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        String(req.user.organization) === String(authorOrg);

      const isTeamMatch =
        interview.visibility === 'team_only' &&
        req.user?.groupId &&
        authorTeamId &&
        String(req.user.groupId) === String(authorTeamId);

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    const embedLink = convertYouTubeToEmbed(interview.video_link);

    const { groupMembers, leaderId, leaderName } = await getLeaderAssignContext(req);
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    return res.render('unit_views/single_interview', {
      layout: 'unitviewlayout',

      _id: interview._id.toString(),
      unitType: 'interview',
      interview_title: interview.interview_title,
      short_summary: interview.short_summary,
      full_summary: interview.full_summary,
      interview_link: interview.video_link || '',
      embedLink,
      interview_content: interview.transcript || 'Transcript will be available soon.',

      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      main_topic: interview.main_topic,
      secondary_topics: interview.secondary_topics || [],
      sub_topic: interview.sub_topic,

      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: typeof req.isAuthenticated === 'function' ? req.isAuthenticated() : !!req.user,

      isLeader,
      isGroupMember,
      isMember,

      tagSuccess: req.query.tag === 'ok',

      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      ...adminSuggest,
      suggestionSuccess: req.query.suggested === '1',
      suggestedUnitId: req.query.unitId || '',
      suggestedUnitType: req.query.unitType || '',

      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });
  } catch (err) {
    console.error('💥 Error fetching interview:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the interview.',
    });
  }
},








      
    
    

viewPromptset: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📚 Fetching prompt set with ID: ${id}`);

    // 1) Load the prompt set
    const promptSet = await PromptSet.findById(id);
    if (!promptSet) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Prompt Set Not Found',
        errorMessage: `The prompt set with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author (profile for name/image) + actual doc for org/team checks
    const authorIdRaw = promptSet.author?.id || promptSet.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    const author = await resolveAuthorById(authorId);

    if (!authorId || !author) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this prompt set could not be found.`,
      });
    }

    // 3) Ownership & current user
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || req.user?.accessLevel || null;

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);
    const isLeader = currentMembership === 'leader';

    // Fetch the author's org/team from their actual doc
    let authorOrg = null;
    let authorGroupId = null;

    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);

    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id; // leaders use their own id as group id
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    // 4) Additional membership checks
    const isGroupMember = !!(await GroupMember.findById(currentUserId).select('_id').lean());
    const isPaidIndividual =
      req.user?.membershipType === 'member' &&
      ['paid_individual', 'contributor_individual'].includes(req.user?.accessLevel);

    // 5) Visibility check
    let isAuthorizedToViewFullContent = false;

    if (promptSet.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      const isOrgMatch =
        promptSet.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      const isTeamMatch =
        promptSet.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      // Prompt sets are more permissive in your system (leader, group_member, paid individual)
      isAuthorizedToViewFullContent =
        isOwner || isLeader || isGroupMember || isPaidIndividual || isOrgMatch || isTeamMatch;
    }

    // 6) Leader context for assignment UI (if leader)
    let groupMembers = [];
    let leaderId = undefined;
    let leaderName = undefined;

    if (isLeader && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId)
        .select('_id groupLeaderName username')
        .lean();

      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('name _id')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 7) ✅ Org Admin suggestion context
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    // 8) Render
    return res.render('unit_views/single_promptset', {
      layout: 'unitviewlayout',
      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,

      // identity & content
      _id: promptSet._id.toString(),
      unitType: 'promptset',
      promptset_title: promptSet.promptset_title,
      short_summary: promptSet.short_summary,
      full_summary: promptSet.full_summary,
      main_topic: promptSet.main_topic,
      secondary_topics: promptSet.secondary_topics || [],
      sub_topic: promptSet.sub_topic,

      // optional metadata
      target_audience: promptSet.target_audience,
      characteristics: promptSet.characteristics,
      purpose: promptSet.purpose,
      suggested_frequency: promptSet.suggested_frequency,

      // prompts / headlines
      prompts: [
        promptSet.Prompt1, promptSet.Prompt2, promptSet.Prompt3, promptSet.Prompt4, promptSet.Prompt5,
        promptSet.Prompt6, promptSet.Prompt7, promptSet.Prompt8, promptSet.Prompt9, promptSet.Prompt10,
        promptSet.Prompt11, promptSet.Prompt12, promptSet.Prompt13, promptSet.Prompt14, promptSet.Prompt15,
        promptSet.Prompt16, promptSet.Prompt17, promptSet.Prompt18, promptSet.Prompt19, promptSet.Prompt20,
      ],
      prompt_headlines: [
        promptSet.prompt_headline1, promptSet.prompt_headline2, promptSet.prompt_headline3, promptSet.prompt_headline4, promptSet.prompt_headline5,
        promptSet.prompt_headline6, promptSet.prompt_headline7, promptSet.prompt_headline8, promptSet.prompt_headline9, promptSet.prompt_headline10,
        promptSet.prompt_headline11, promptSet.prompt_headline12, promptSet.prompt_headline13, promptSet.prompt_headline14, promptSet.prompt_headline15,
        promptSet.prompt_headline16, promptSet.prompt_headline17, promptSet.prompt_headline18, promptSet.prompt_headline19, promptSet.prompt_headline20,
      ],
      prompt0: promptSet.Prompt0,
      prompt_headline0: promptSet.prompt_headline0,

      options: {
        clarify_topic: promptSet.clarify_topic,
        topics_and_enlightenment: promptSet.topics_and_enlightenment,
        challenge: promptSet.challenge,
        instructions: promptSet.instructions,
        time: promptSet.time,
        permission: promptSet.permission,
      },

      // author card
      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      // flags
      isOwner,
      isLeader,
      isAuthenticated: typeof req.isAuthenticated === 'function' ? req.isAuthenticated() : !!req.user,
      isAuthorizedToViewFullContent,

      isGroupMemberOrLeader: isLeader || currentMembership === 'group_member',
      isGroupMemberOrMember: currentMembership === 'group_member' || currentMembership === 'member',

      // ✅ Admin suggest vars (top-level)
      ...adminSuggest,
// ✅ Suggestion success banner (after redirect back)
suggestionSuccess: req.query.suggested === '1',
suggestedUnitId: req.query.unitId || '',
suggestedUnitType: req.query.unitType || '',
      // leader UI data (if your HBS uses it)
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',
    });

  } catch (err) {
    console.error('Error fetching prompt set:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the prompt set.',
    });
  }
},

    
    
    

    
viewExercise: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📘 Fetching exercise with ID: ${id}`);

    // 1) Load the exercise
    const exercise = await Exercise.findById(id);
    if (!exercise) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Exercise Not Found',
        errorMessage: `The exercise with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author (creator) for sidebar
    const authorIdRaw = exercise.author?.id || exercise.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    if (!authorId) {
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'Exercise author is missing.',
      });
    }

    const creator = await resolveAuthorById(authorId);

    // 3) Current user helpers
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;

    const isLeader = currentMembership === 'leader';
    const isGroupMember = currentMembership === 'group_member';
    const isMember = currentMembership === 'member';

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    // 4) Access control
    let authorOrg = null;
    let authorGroupId = null;

    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);

    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id;
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (exercise.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        exercise.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      isTeamMatch =
        exercise.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log('🔒 Access breakdown (exercise):', {
      isOwner,
      isOrgMatch,
      isTeamMatch,
      isAuthorizedToViewFullContent
    });

    // 5) Leader context for assignment UI
    let groupMembers = [];
    let leaderId = undefined;
    let leaderName = undefined;

    if (isLeader && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId)
        .select('_id groupLeaderName username')
        .lean();

      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 6) Org Admin suggestion context
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    // 7) Normalize document uploads for the view
    const rawDocs = Array.isArray(exercise.document_uploads)
      ? exercise.document_uploads.filter(Boolean)
      : exercise.document_uploads
        ? [exercise.document_uploads]
        : [];

    const extensionMap = {
      'MS Word': '.docx',
      'MS Excel': '.xlsx',
      'MS PowerPoint': '.pptx',
      'PDF': '.pdf',
      'Mural': '.pdf'
    };

    const fallbackExt = extensionMap[exercise.file_format] || '';

    const document_uploads = rawDocs.map((doc, index) => {
      const url = typeof doc === 'string' ? doc : (doc?.url || '');
      let filename = typeof doc === 'object' && doc?.filename ? doc.filename : '';

      if (!filename && url) {
        try {
          const parsed = new URL(url, 'https://www.twennie.com');
          filename = decodeURIComponent(parsed.pathname.split('/').pop() || '');
        } catch {
          filename = decodeURIComponent((url.split('?')[0].split('/').pop()) || '');
        }
      }

      if (!filename) {
        filename = `${exercise.exercise_title || 'exercise-download'}-${index + 1}`;
      }

      if (!/\.[a-z0-9]+$/i.test(filename) && fallbackExt) {
        filename += fallbackExt;
      }

      return {
        url,
        filename
      };
    });

    // 8) Render
    return res.render('unit_views/single_exercise', {
      layout: 'unitviewlayout',

      _id: exercise._id.toString(),
      unitType: 'exercise',
      exercise_title: exercise.exercise_title,
      short_summary: exercise.short_summary,
      full_summary: exercise.full_summary,
      time_required: exercise.time_required,
      file_format: exercise.file_format,
      document_uploads,

      creator: {
        name: creator?.name || 'Unknown Creator',
        image: creator?.image || '/images/default-avatar.png',
      },

      main_topic: exercise.main_topic,
      secondary_topics: exercise.secondary_topics || [],
      sub_topic: exercise.sub_topic,

      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,

      isLeader,
      isGroupMember,
      isMember,

      

      tagSuccess: req.query.tag === 'ok',

      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      ...adminSuggest,
      suggestionSuccess: req.query.suggested === '1',
      suggestedUnitId: req.query.unitId || '',
      suggestedUnitType: req.query.unitType || '',

      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });

  } catch (err) {
    console.error('💥 Error fetching exercise:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the exercise.',
    });
  }
},



    
    
    
    
 viewTemplate: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📄 Fetching template with ID: ${id}`);

    // 1) Load template
    const template = await Template.findById(id);
    if (!template) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Template Not Found',
        errorMessage: `The template with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author
    const authorIdRaw = template.author?.id || template.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    const author = await resolveAuthorById(authorId);

    if (!authorId || !author) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this template could not be found.`,
      });
    }

    // 3) Ownership & current user
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;

    const isLeader = currentMembership === 'leader';
    const isGroupMember = currentMembership === 'group_member';
    const isMember = currentMembership === 'member';

    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    // 4) Access control
    let authorOrg = null;
    let authorGroupId = null;

    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);

    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id;
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (template.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        template.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      isTeamMatch =
        template.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log('🔒 Access breakdown (template):', {
      isOwner,
      isOrgMatch,
      isTeamMatch,
      isAuthorizedToViewFullContent
    });

    // 5) Leader context for assignments
    let groupMembers = [];
    let leaderId;
    let leaderName;

    if (isLeader && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId)
        .select('_id groupLeaderName username')
        .lean();

      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 6) Org Admin suggestion context
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    // 7) Normalize document uploads
    const toFilename = (u) => {
      try {
        const last = (u || '').split('/').pop() || 'download';
        return decodeURIComponent(last);
      } catch {
        return 'download';
      }
    };

    let documentUploads = [];
    const rawDocs = template.documentUploads;

    if (Array.isArray(rawDocs)) {
      documentUploads = rawDocs.map(d =>
        typeof d === 'string'
          ? { url: d, filename: toFilename(d) }
          : { url: d.url || '', filename: d.filename || toFilename(d.url || '') }
      );
    } else if (rawDocs) {
      documentUploads = [
        typeof rawDocs === 'string'
          ? { url: rawDocs, filename: toFilename(rawDocs) }
          : { url: rawDocs.url || '', filename: rawDocs.filename || toFilename(rawDocs.url || '') }
      ];
    }

    // 8) Render
    return res.render('unit_views/single_template', {
      layout: 'unitviewlayout',

      _id: template._id.toString(),
      unitType: 'template',
      template_title: template.template_title,
      short_summary: template.short_summary,
      full_summary: template.full_summary,
      template_content: template.template_content,
      documentUploads,

      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      main_topic: template.main_topic,
      secondary_topics: template.secondary_topics || [],
      sub_topic: template.sub_topic,

      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,

      isLeader,
      isGroupMember,
      isMember,

      tagSuccess: req.query.tag === 'ok',

      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      ...adminSuggest,
      suggestionSuccess: req.query.suggested === '1',
      suggestedUnitId: req.query.unitId || '',
      suggestedUnitType: req.query.unitType || '',

      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });

  } catch (err) {
    console.error('💥 Error fetching template:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the template.',
    });
  }
},



viewUpcoming: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🟣 Fetching upcoming unit: ${id}`);

    const upcoming = await UpcomingUnit.findById(id).lean();
    if (!upcoming) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Upcoming Unit Not Found',
        errorMessage: `The upcoming unit with ID ${id} does not exist.`,
      });
    }

    // If this doc somehow survived publish, bounce to the live unit.
    if (upcoming.status === 'released' && upcoming.published_unit_ref?.id) {
      const pathMap = {
        article: 'articles', video: 'videos', interview: 'interviews',
        exercise: 'exercises', template: 'templates', prompt_set: 'promptsets',
        micro_course: 'microcourses', micro_study: 'microstudies',
      };
      const modelPath = pathMap[upcoming.published_unit_ref.model];
      if (modelPath) return res.redirect(`/${modelPath}/view/${upcoming.published_unit_ref.id}`);
    }

    const isAuthenticated = !!req.user;
    const isLeader = req.user?.membershipType === 'leader';
    const canPublish = isLeader; // leaders see "publish now"

    // Lightweight teaser rule
    const isAuthorizedToViewFullContent =
      upcoming.visibility === 'all_members' ? true : isAuthenticated;

    // Leader context for assign form
    let groupMembers = [];
    let leaderName = null;
    let leaderId = null;

    if (isLeader) {
      // Use req.user.id (your session shim sets both id and _id as strings)
      const leaderDoc = await Leader.findById(req.user.id || req.user._id).select('groupLeaderName username').lean();
      if (leaderDoc) {
        const leaderObjectId = leaderDoc._id;
        groupMembers = await GroupMember.find({ groupId: leaderObjectId })
          .select('_id name')
          .lean();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
        leaderId = leaderObjectId.toString();
        console.log("🧑‍🤝‍🧑 Group members for upcoming:", groupMembers.length);
      }
    }

    return res.render('unit_views/upcomingunit', {
      layout: 'unitviewlayout',
      _id: upcoming._id.toString(),
      title: upcoming.title,
      teaser: upcoming.teaser,
      long_teaser: upcoming.long_teaser,
      unit_type: upcoming.unit_type,
      main_topic: upcoming.main_topic,
      secondary_topics: upcoming.secondary_topics || [],
      sub_topic: upcoming.sub_topic,
      status: upcoming.status,
      projected_release_at: upcoming.projected_release_at,
      image: upcoming.image || { url: '/images/default-upcoming.png' },
      published_unit_ref: upcoming.published_unit_ref || null,

      // view flags
      isAuthenticated,
      isAuthorizedToViewFullContent,
      isLeader,
      isGroupMemberOrLeader:
        req.user?.membershipType === 'leader' || req.user?.membershipType === 'group_member',
      isGroupMemberOrMember:
        req.user?.membershipType === 'group_member' || req.user?.membershipType === 'member',
      isOwner: false, // upcoming has no author binding

      // leader assign context
      groupMembers,
      leaderId: leaderId || req.user?._id?.toString(),
      leaderName: leaderName || req.user?.username || 'You',

      tagSuccess: req.query.tag === 'ok',

      // publish
      canPublish,

      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('💥 Error fetching upcoming unit:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the upcoming unit.',
    });
  }
},


viewMission: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`[viewMission] Fetching mission with ID: ${id}`);

    const mission = await Mission.findById(id).lean();
    if (!mission) {
      console.warn(`[viewMission] Mission with ID ${id} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Mission Not Found',
        errorMessage: `The mission with ID ${id} does not exist.`,
      });
    }

    // --- Basic membership gate ---
    const membershipType = req.user?.membershipType || null;
    const accessLevel    = req.user?.accessLevel || null;

    const isLeader         = membershipType === 'leader';
    const isGroupMember    = membershipType === 'group_member';
    const isMember         = membershipType === 'member';
    const isPaidIndividual = accessLevel === 'paid_individual';

    const canViewMission = isLeader || isGroupMember || isPaidIndividual;

    if (!req.user || !canViewMission) {
      console.log(
        '[viewMission] Access denied for mission view. membershipType:',
        membershipType,
        'accessLevel:',
        accessLevel
      );
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'Missions are available to leaders, group members, and paid individual members.',
      });
    }

    // --- Badge fields ---
    const category = mission.category || 'other';
    const badge_name = (mission.badge_name && String(mission.badge_name).trim())
      ? String(mission.badge_name).trim()
      : '';

    const badgeImagePath =
      mission.badgeImagePath ||
      mission.badge_image ||
      mission.badgeImage ||
      getMissionBadgePath(category);

    // --- Owner + creator (for sidebar) ---
    const currentUserId = (req.user?._id || req.user?.id)?.toString();

    let rawOwnerId =
      mission.createdBy ||
      mission.created_by ||
      mission.creatorId ||
      mission.creator ||
      (mission.author && (mission.author.id || mission.author._id || mission.author)) ||
      mission.owner ||
      null;

    if (rawOwnerId && typeof rawOwnerId === 'object' && rawOwnerId.toString) {
      rawOwnerId = rawOwnerId.toString();
    } else if (typeof rawOwnerId === 'string') {
      rawOwnerId = rawOwnerId;
    } else {
      rawOwnerId = null;
    }

    const ownerId = rawOwnerId;
    const isOwner = !!(currentUserId && ownerId && currentUserId === ownerId);

    let creator = null;
    if (ownerId) {
      creator = await resolveAuthorById(ownerId);
    }

    // --- Build linked Twennie learning units for display ---
    let learningUnits = [];
    if (Array.isArray(mission.twennie_learning_units) && mission.twennie_learning_units.length) {
      const lookups = mission.twennie_learning_units.map(async (lu) => {
        if (!lu || !lu.unit_type || !lu.unit_id) return null;

        let Model = null;
        let titleField = null;
        let basePath = null;
        let displayType = null;

        switch (lu.unit_type) {
          case 'article':
            Model = Article; titleField = 'article_title'; basePath = '/unitviews/articles/view'; displayType = 'Article';
            break;
          case 'video':
            Model = Video; titleField = 'video_title'; basePath = '/unitviews/videos/view'; displayType = 'Video';
            break;
          case 'interview':
            Model = Interview; titleField = 'interview_title'; basePath = '/unitviews/interviews/view'; displayType = 'Interview';
            break;
          case 'promptset':
            Model = PromptSet; titleField = 'promptset_title'; basePath = '/unitviews/promptsets/view'; displayType = 'Prompt Set';
            break;
          case 'exercise':
            Model = Exercise; titleField = 'exercise_title'; basePath = '/unitviews/exercises/view'; displayType = 'Exercise';
            break;
          case 'template':
            Model = Template; titleField = 'template_title'; basePath = '/unitviews/templates/view'; displayType = 'Template';
            break;
          case 'nugget':
            Model = Nugget; titleField = 'title'; basePath = '/unitviews/nuggets/view'; displayType = 'Nugget';
            break;
          case 'mission':
            Model = Mission; titleField = 'mission_title'; basePath = '/unitviews/missions/view'; displayType = 'Mission';
            break;
          default:
            return null;
        }

        try {
          const doc = await Model.findById(lu.unit_id).lean();
          if (!doc) return null;

          const title = doc[titleField] || doc.title || '(untitled)';

          return {
            unit_type: lu.unit_type,
            title,
            displayType,
            url: `${basePath}/${doc._id}`,
          };
        } catch (e) {
          console.error('[viewMission] Error loading linked unit:', e.message || e);
          return null;
        }
      });

      const resolved = await Promise.all(lookups);
      learningUnits = resolved.filter(Boolean);
    }

    // --- Leader assign context (shared helper) ---
    const {
      isLeader: assignIsLeader,
      groupMembers,
      leaderId,
      leaderName,
    } = await getLeaderAssignContext(req);

    // ✅ Org Admin suggestion context
    const adminSuggest = await buildOrgLeaderListForAdmin(req);

    // --- Render single_mission view ---
    return res.render('unit_views/single_mission', {
      layout: 'unitviewlayout',

      // identity
      _id: mission._id.toString(),
      unitType: 'mission',

      // title + summaries
      mission_title: mission.mission_title,
      short_purpose: mission.short_purpose || '',
      full_summary: mission.full_summary || '',

      // meta
      status: mission.status,
      category,
      timeframe: mission.timeframe,
      estimated_effort_hours: mission.estimated_effort_hours,
      open_to: mission.open_to,

      // badge display
      badge_name,
      badgeImagePath,

      // purpose / why / background
      purpose: mission.purpose,
      why_it_matters: mission.why_it_matters,
      background: mission.background,

      // details
      department_requesting: mission.department_requesting,
      job_number: mission.job_number,
      budget_amount: mission.budget_amount,
      due_date: mission.due_date,
      visibility: mission.visibility,
      main_topic: mission.main_topic,
      secondary_topics: mission.secondary_topics || [],

      // approvals / instructions / deliverables / contacts
      approvals_required: mission.approvals_required || [],
      task_instructions: mission.task_instructions || [],
      deliverables_checklist: mission.deliverables_checklist || [],
      contacts: mission.contacts || [],

      // linked Twennie learning units
      learningUnits,

      // tags
      tagsForUnit: mission.tagsForUnit || [],

      // creator for sidebar
      creator: creator
        ? { name: creator.name || 'Unknown Author', image: creator.image || '/images/default-avatar.png' }
        : null,

      // flags
      isOwner,
      isLeader: assignIsLeader,
      isGroupMemberOrLeader: isLeader || isGroupMember,
      isGroupMemberOrMember: isGroupMember || isMember,
      isGroupMemberOrLeaderOrMember: isLeader || isGroupMember || isMember,

      // ✅ Admin suggest vars (top-level)
      ...adminSuggest,
// ✅ Suggestion success banner (after redirect back)
suggestionSuccess: req.query.suggested === '1',
suggestedUnitId: req.query.unitId || '',
suggestedUnitType: req.query.unitType || '',
      // leader assignment UI
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : null,
    });

  } catch (err) {
    console.error('💥 Error fetching mission:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the mission.',
    });
  }
},








};    