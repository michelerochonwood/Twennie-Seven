const Mission = require('../models/unit_models/mission');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

const MemberProfile = require('../models/profile_models/member_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const OrganizationProfile = require('../models/profile_models/organization_profile');

function canAccessMineAndMissions(req) {
  const membershipType = req.user?.membershipType;

  return membershipType === 'leader' || membershipType === 'group_member';
}

function isLeaderOrGroupMember(req) {
  const membershipType = req.user?.membershipType;

  return membershipType === 'leader' || membershipType === 'group_member';
}

function normalizeImg(img) {
  if (!img) return '/images/default-avatar.png';
  if (/^https?:\/\//i.test(img)) return img;
  return img.startsWith('/') ? img : '/' + img;
}

function dedupeSectionedMissions(sectionedMissions) {
  const seenMissionIds = new Set();

  return sectionedMissions.map(section => {
    const dedupedMissions = (section.missions || []).filter(mission => {
      const uniqueKey = mission._id
        ? String(mission._id)
        : `${mission.mission_title || 'untitled'}:${mission.authorId || 'no-author'}`;

      if (seenMissionIds.has(uniqueKey)) return false;
      seenMissionIds.add(uniqueKey);
      return true;
    });

    return {
      ...section,
      missions: dedupedMissions
    };
  });
}

async function resolveCreatorById(authorId) {
  try {
    let profile = await LeaderProfile.findOne({ leaderId: authorId })
      .select('profileImage name')
      .lean();

    if (profile) {
      return {
        name: profile.name || 'Leader',
        image: normalizeImg(profile.profileImage),
      };
    }

    profile = await GroupMemberProfile.findOne({ groupMemberId: authorId })
      .select('profileImage name')
      .lean();

    if (profile) {
      return {
        name: profile.name || 'Group Member',
        image: normalizeImg(profile.profileImage),
      };
    }

    profile = await MemberProfile.findOne({ memberId: authorId })
      .select('profileImage name')
      .lean();

    if (profile) {
      return {
        name: profile.name || 'Member',
        image: normalizeImg(profile.profileImage),
      };
    }
  } catch (err) {
    console.error('Error resolving mission creator profile:', err);
  }

  return { name: 'Unknown Creator', image: '/images/default-avatar.png' };
}

async function resolveCreatorAndOrgById(authorId) {
  const creator = await resolveCreatorById(authorId);

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
    console.error('Error resolving organization for mission creator:', error);
  }

  return {
    ...creator,
    organizationId,
    organizationName,
    organizationLogo
  };
}
// Generic helper for category pages
// Generic helper for category pages (rewritten cleanly; uses GroupMember.leader + org ObjectId matching)
async function renderMissionList(req, res, options) {
  const {
    category,
    viewName,
    pageTitle,
    shortSummary,
    longSummary,
  } = options;

  try {
    if (!canAccessMineAndMissions(req)) {
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'Missions are available to paid members only.',
      });
    }

    const user = req.user || null;
    const loggedIn = !!user;
    const membershipType = user?.membershipType || null;
    const accessLevel = user?.accessLevel || null;
    const userId = (user?._id || user?.id)?.toString() || null;

    const leaderOrGroup =
      membershipType === 'leader' || membershipType === 'group_member';

    const paidIndividual =
      membershipType === 'member' &&
      (accessLevel === 'paid_individual' ||
        accessLevel === 'contributor_individual');

    const freeIndividual =
      membershipType === 'member' && accessLevel === 'free_individual';

    const isPaid = leaderOrGroup || paidIndividual;
    const isFree = freeIndividual;

    let missions = await Mission.find({ category })
      .sort({ created_at: -1 })
      .lean();

    missions = missions.map((m) => ({
      ...m,
      authorId:
        m.authorId ||
        m.author?.id ||
        m.author ||
        m.createdBy ||
        m.created_by ||
        null,
      visibility: m.visibility || 'all_members',
    }));

    const normalize = (value) =>
      (value || '').toString().trim().toLowerCase();

    const emailDomain = (email) => {
      if (!email || !String(email).includes('@')) return null;
      return String(email).split('@').pop().toLowerCase();
    };

    let leaderDoc = null;
    let groupMemberDoc = null;
    let memberDoc = null;

    if (userId) {
      try {
        leaderDoc = await Leader.findById(userId).lean();
        if (!leaderDoc) {
          groupMemberDoc = await GroupMember.findById(userId).lean();
        }
        if (!leaderDoc && !groupMemberDoc) {
          memberDoc = await Member.findById(userId).lean();
        }
      } catch (err) {
        console.error('Error loading current mission viewer:', err);
      }
    }

    const myGroupAuthorIds = new Set();

    if (leaderDoc) {
      myGroupAuthorIds.add(String(leaderDoc._id));

      const membersByLeader = await GroupMember.find({ leader: leaderDoc._id })
        .select('_id')
        .lean();

      if (membersByLeader.length) {
        membersByLeader.forEach((m) => myGroupAuthorIds.add(String(m._id)));
      } else if (leaderDoc.groupName) {
        const membersByGroupName = await GroupMember.find({
          groupName: leaderDoc.groupName,
        })
          .select('_id')
          .lean();

        membersByGroupName.forEach((m) => myGroupAuthorIds.add(String(m._id)));
      }
    } else if (groupMemberDoc) {
      if (groupMemberDoc.leader) {
        myGroupAuthorIds.add(String(groupMemberDoc.leader));
      }

      myGroupAuthorIds.add(String(groupMemberDoc._id));

      const peerQuery = groupMemberDoc.leader
        ? { leader: groupMemberDoc.leader }
        : groupMemberDoc.groupName
          ? { groupName: groupMemberDoc.groupName }
          : null;

      if (peerQuery) {
        const peers = await GroupMember.find(peerQuery).select('_id').lean();
        peers.forEach((p) => myGroupAuthorIds.add(String(p._id)));
      }
    }

    const me = leaderDoc || groupMemberDoc || memberDoc || {};
    const myOrgKey =
      me.organization
        ? String(me.organization)
        : normalize(me.organizationId) || emailDomain(me.email) || null;

    const authorOrgKeyCache = new Map();

    async function getAuthorOrgKey(authorId) {
      const cacheKey = String(authorId);
      if (authorOrgKeyCache.has(cacheKey)) {
        return authorOrgKeyCache.get(cacheKey);
      }

      let aLeader = null;
      let aGroupMember = null;
      let aMember = null;

      try {
        aLeader = await Leader.findById(authorId)
          .select('organization organizationId organizationName email leader groupId groupName')
          .lean();

        if (!aLeader) {
          aGroupMember = await GroupMember.findById(authorId)
            .select('organization organizationId organizationName email leader groupId groupName')
            .lean();
        }

        if (!aLeader && !aGroupMember) {
          aMember = await Member.findById(authorId)
            .select('organization organizationId organizationName email')
            .lean();
        }
      } catch (err) {
        console.error('Error resolving mission author org key:', err);
      }

      let doc = aLeader || aGroupMember || aMember || {};

      let orgKey =
        doc.organization
          ? String(doc.organization)
          : normalize(doc.organizationId) || emailDomain(doc.email) || null;

      if (!orgKey && aGroupMember) {
        try {
          const parentLeaderId = aGroupMember.leader || aGroupMember.groupId || null;

          if (parentLeaderId) {
            const parentLeader = await Leader.findById(parentLeaderId)
              .select('organization organizationId organizationName email')
              .lean();

            if (parentLeader) {
              orgKey =
                parentLeader.organization
                  ? String(parentLeader.organization)
                  : normalize(parentLeader.organizationId) ||
                    emailDomain(parentLeader.email) ||
                    null;
            }
          }

          if (!orgKey && aGroupMember.groupName) {
            const parentLeaderByGroupName = await Leader.findOne({
              groupName: aGroupMember.groupName,
            })
              .select('organization organizationId organizationName email')
              .lean();

            if (parentLeaderByGroupName) {
              orgKey =
                parentLeaderByGroupName.organization
                  ? String(parentLeaderByGroupName.organization)
                  : normalize(parentLeaderByGroupName.organizationId) ||
                    emailDomain(parentLeaderByGroupName.email) ||
                    null;
            }
          }
        } catch (err) {
          console.error('Error resolving parent leader org key:', err);
        }
      }

      authorOrgKeyCache.set(cacheKey, orgKey);
      return orgKey;
    }

    const myMissions = missions.filter(
      (m) => userId && m.authorId && String(m.authorId) === userId
    );

    const groupMissions = missions.filter(
      (m) => m.authorId && myGroupAuthorIds.has(String(m.authorId))
    );

    let orgMissions = [];
    if (myOrgKey) {
      const uniqueAuthorIds = [
        ...new Set(
          missions.map((m) => (m.authorId ? String(m.authorId) : null)).filter(Boolean)
        ),
      ];

      const orgKeyMap = new Map();
      for (const aid of uniqueAuthorIds) {
        orgKeyMap.set(aid, await getAuthorOrgKey(aid));
      }

      orgMissions = missions.filter((m) => {
        const visibility = m.visibility || 'all_members';
        if (!['organization_only', 'all_members'].includes(visibility)) {
          return false;
        }

        const authorOrgKey = orgKeyMap.get(String(m.authorId));
        return !!authorOrgKey && authorOrgKey === myOrgKey;
      });
    }

    const twennieMissions = missions.filter(
      (m) => (m.visibility || 'all_members') === 'all_members'
    );

    const creatorMetaCache = new Map();




async function getCreatorMeta(authorId) {
  const key = String(authorId);
  if (creatorMetaCache.has(key)) return creatorMetaCache.get(key);

  const meta = await resolveCreatorAndOrgById(authorId);
  creatorMetaCache.set(key, meta);
  return meta;
}

async function enrichList(list) {
  const result = [];

  for (const m of list) {
    let creatorName = 'Unknown Creator';
    let creatorImage = '/images/default-avatar.png';
    let organizationId = null;
    let organizationName = '';
    let organizationLogo = '/images/default-organization-logo.png';

    if (m.authorId) {
      const meta = await getCreatorMeta(m.authorId);
      creatorName = meta.name;
      creatorImage = meta.image;
      organizationId = meta.organizationId || null;
      organizationName = meta.organizationName || '';
      organizationLogo = meta.organizationLogo || '/images/default-organization-logo.png';
    }

    result.push({
      ...m,
      creatorName,
      creatorImage,
      organizationId,
      organizationName,
      organizationLogo,
      loggedIn,
      isLeaderOrGroupMember: leaderOrGroup,
      isPaid,
      isFree,
    });
  }

  return result;
}

    const myMissionsEnriched = await enrichList(myMissions);
    const groupMissionsEnriched = await enrichList(groupMissions);
    const orgMissionsEnriched = await enrichList(orgMissions);
    const twennieMissionsEnriched = await enrichList(twennieMissions);

    const sectionedMissions = dedupeSectionedMissions([
      {
        sectionTitle: 'missions I created',
        missions: myMissionsEnriched,
        emptyMessage:
          'When you create missions, the ones you authored will show here. Use your missions to guide your own focus during light workloads.',
      },
      {
        sectionTitle: 'missions created by my group',
        missions: groupMissionsEnriched,
        emptyMessage:
          "Once your group starts creating missions, you'll see them here. Use group missions to coordinate how your group spends slow periods.",
      },
      {
        sectionTitle: 'missions created by my organization',
        missions: orgMissionsEnriched,
        emptyMessage:
          'As people across your organization create missions and share them with the broader firm, they will appear here.',
      },
      {
        sectionTitle: "Twennie's missions",
        missions: twennieMissionsEnriched,
        emptyMessage:
          'Twennie will be publishing missions for this category soon. Check back to see new ideas for how to spend slow periods strategically.',
      },
    ]);

    return res.render(viewName, {
      layout: 'unitviewlayout',
      title: pageTitle,
      shortSummary,
      longSummary,
      sectionedMissions,
      loggedIn,
      isLeaderOrGroupMember: leaderOrGroup,
      isPaid,
      isFree,
    });
  } catch (err) {
    console.error(`[${category} missions] error:`, err.stack || err.message || err);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading missions.',
    });
  }
}


// Helper: build mission data from form body
function buildMissionDataFromBody(req) {
  let taskInstructions = [];

  if (req.body.task_instructions) {
    const rawTasks = Array.isArray(req.body.task_instructions)
      ? req.body.task_instructions
      : Object.values(req.body.task_instructions);

    taskInstructions = rawTasks
      .map((task) => {
        const heading = (task.heading || '').trim();
        const instructionsText = task.instructions || '';
        const instructions = String(instructionsText)
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);

        return {
          heading,
          instructions,
        };
      })
      .filter((task) => task.heading || task.instructions.length);
  }

  const deliverablesChecklist = req.body.deliverables_checklist
    ? String(req.body.deliverables_checklist)
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
    : [];

  return {
    status: req.body.status || 'one time mission',
    visibility: req.body.visibility || 'organization_only',

    mission_title: (req.body.mission_title || '').trim(),
    badge_name: (req.body.badge_name || '').trim(),
    purpose: (req.body.purpose || '').trim(),
    summary: (req.body.summary || '').trim(),
    additional_instructions: (req.body.additional_instructions || '').trim(),

    department_requesting: (req.body.department_requesting || '').trim(),
    open_to: (req.body.open_to || '').trim(),
    timeframe: (req.body.timeframe || '').trim(),
    estimated_effort_hours: req.body.estimated_effort_hours
      ? Number(req.body.estimated_effort_hours)
      : undefined,
    job_number: (req.body.job_number || '').trim(),
    budget_amount: (req.body.budget_amount || '').trim(),
    due_date: req.body.due_date ? new Date(req.body.due_date) : undefined,

    task_instructions: taskInstructions,
    deliverables_checklist: deliverablesChecklist,

    category: req.body.category || 'internal_improvement',
  };
}


module.exports = {
  // Mission Control unchanged...
  missionControl: async (req, res) => {
    try {
      if (!canAccessMineAndMissions(req)) {
        return res.status(403).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Access Restricted',
          errorMessage: 'Mission Control is available to paid members only.',
        });
      }

      return res.render('unit_views/missioncontrol_category', {
        layout: 'unitviewlayout',
        title: 'Mission Control',
        shortSummary: 'See and manage missions across all categories.',
        longSummary:
          'Mission Control is where you’ll eventually track missions by status, category, and assignee. ' +
          'For now, use it as a hub to jump into each mission category.',
        loggedIn: !!req.user,
      });
    } catch (err) {
      console.error('missionControl error:', err.stack || err.message);
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading Mission Control.',
      });
    }
  },



  // Category lists
  learningMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'learning',
      viewName: 'unit_views/missions_learning',
      pageTitle: 'Learning Missions',
      shortSummary:
        'Missions that turn slow periods into focused learning sprints.',
      longSummary:
        'Use learning missions when you want people to build skills, explore a new topic, or work ' +
        'through Twennie units with a specific purpose while the workload is light.',
    }),

  researchMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'research',
      viewName: 'unit_views/missions_research',
      pageTitle: 'Research Missions',
      shortSummary:
        'Missions focused on market, client, and opportunity research.',
      longSummary:
        'Use research missions when you need to gather intel, understand a client, or explore a market ' +
        'before committing resources. These missions often feed directly into Nuggets and strategy work.',
    }),

  businessDevelopmentMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'business_development',
      viewName: 'unit_views/missions_businessdevelopment',
      pageTitle: 'Business Development Missions',
      shortSummary: 'Missions that generate and advance opportunities.',
      longSummary:
        'Use business development missions to drive proactive outreach, strengthen relationships, and move ' +
        'opportunities from early curiosity toward real pursuits.',
    }),

  internalImprovementMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'internal_improvement',
      viewName: 'unit_views/missions_internal_improvements',
      pageTitle: 'Internal Improvement Missions',
      shortSummary:
        'Missions that improve internal systems, tools, and workflows.',
      longSummary:
        'Use internal improvement missions to tighten processes, remove friction, and make daily work ' +
        'easier and more effective for your team.',
    }),

  clientExperienceMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'client_experience',
      viewName: 'unit_views/missions_clientexperience',
      pageTitle: 'Client Experience Missions',
      shortSummary:
        'Missions that elevate the client’s day-to-day experience.',
      longSummary:
        'Use client experience missions to design better touchpoints, communication, and follow-up. ' +
        'These missions help un-commoditize your services and make clients feel genuinely looked after.',
    }),

  cultureAndPlayMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'culture_play',
      viewName: 'unit_views/missions_cultureandplay',
      pageTitle: 'Culture & Play Missions',
      shortSummary:
        'Missions that build culture, play, and human connection.',
      longSummary:
        'Use culture and play missions to experiment with fun, rituals, and connection that make work ' +
        'feel more human — and projects easier to deliver.',
    }),

  administrativeMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'administrative',
      viewName: 'unit_views/missions_administrative',
      pageTitle: 'Administrative Missions',
      shortSummary:
        'Missions that handle the necessary operational and admin work.',
      longSummary:
        'Use administrative missions to tackle the important-but-not-urgent tasks that keep your firm ' +
        'organized, compliant, and prepared when things get busy again.',
    }),

  communityMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'community',
      viewName: 'unit_views/missions_community',
      pageTitle: 'Community Missions',
      shortSummary: 'Missions that encourage giving and community involvement.',
      longSummary:
        'Use community missions for community outreach, volunteering, and giving.',
    }),

  rogueMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'other',
      viewName: 'unit_views/missions_rogue',
      pageTitle: 'Rogue Missions',
      shortSummary: 'Wild-card missions that don’t fit any one category.',
      longSummary:
        'Use rogue missions for experiments, oddball ideas, and cross-cutting initiatives. These are ' +
        'the “this doesn’t fit anywhere, but it matters” missions.',
    }),

  // Single mission view (unchanged)
  viewMission: async (req, res) => {
    try {
      const { id } = req.params;

      if (!canAccessMineAndMissions(req)) {
        return res.status(403).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Access Restricted',
          errorMessage: 'Mission Control is available to leaders and group members only.',
        });
      }

      const mission = await Mission.findById(id).lean();
      if (!mission) {
        return res.status(404).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Mission Not Found',
          errorMessage: 'The requested mission could not be found.',
        });
      }

      return res.render('unit_views/single_mission', {
        layout: 'unitviewlayout',
        title: mission.mission_title,
        mission,
        loggedIn: !!req.user,
      });
    } catch (err) {
      console.error('viewMission error:', err.stack || err.message);
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading this mission.',
      });
    }
  },
};


