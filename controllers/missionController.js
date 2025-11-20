// controllers/missionController.js

const Mission = require('../models/unit_models/mission');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

const MemberProfile = require('../models/profile_models/member_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');

function isPaidMember(req) {
  const t = req.user?.accessLevel || req.user?.membershipType;
  return ['paid_individual', 'leader', 'group_member'].includes(t);
}

function isLeaderOrGroupMember(req) {
  const t = req.user?.accessLevel || req.user?.membershipType;
  return ['leader', 'group_member'].includes(t);
}

function normalizeImg(img) {
  if (!img) return '/images/default-avatar.png';
  if (/^https?:\/\//i.test(img)) return img;
  return img.startsWith('/') ? img : '/' + img;
}

// Mirror topic controller: resolve author/creator from *profile* models
async function resolveCreatorById(authorId) {
  try {
    // Leader profile by leaderId
    let profile = await LeaderProfile.findOne({ leaderId: authorId })
      .select('profileImage name')
      .lean();
    if (profile) {
      return {
        name: profile.name || 'Leader',
        image: normalizeImg(profile.profileImage),
      };
    }

    // Group Member profile by groupMemberId
    profile = await GroupMemberProfile.findOne({ groupMemberId: authorId })
      .select('profileImage name')
      .lean();
    if (profile) {
      return {
        name: profile.name || 'Group Member',
        image: normalizeImg(profile.profileImage),
      };
    }

    // Individual Member profile by memberId
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

// Generic helper for category pages
async function renderMissionList(req, res, options) {
  const {
    category,    // schema category: 'learning', 'research', 'business_development', etc.
    viewName,    // e.g. 'unit_views/missions_learning'
    pageTitle,   // {{title}} in the view
    shortSummary,
    longSummary,
  } = options;

  try {
    if (!isPaidMember(req)) {
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'Missions are available to paid members only.',
      });
    }

    // ----- BASIC USER / MEMBERSHIP CONTEXT -----
    const user = req.user || null;
    const loggedIn = !!user;
    const membershipType = user?.membershipType || null;
    const accessLevel = user?.accessLevel || null;

    // Same logic you use elsewhere for bytopic views
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

    // 1) Fetch all missions in this category
    let missions = await Mission.find({ category })
      .sort({ created_at: -1 }) // from schema
      .lean();

    // 2) Normalize authors + visibility
    missions = missions.map((m) => ({
      ...m,
      authorId:
        m.authorId ||
        m.author?.id ||
        m.author ||
        m.createdBy ||
        m.created_by ||
        null,
      visibility: m.visibility || 'all_members', // default
    }));

    // ---- BEGIN: smarter segmentation by authorship + visibility ----

    const userId = user?.id || req.session?.user?.id || null;

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
      if (userId) {
        leaderDoc = await Leader.findById(userId).lean();
        if (!leaderDoc) groupMemberDoc = await GroupMember.findById(userId).lean();
        if (!leaderDoc && !groupMemberDoc) memberDoc = await Member.findById(userId).lean();
      }
    } catch (_) {
      // ignore lookup errors
    }

    // Build group roster: includes the leader + all group members
    let myGroupAuthorIds = new Set();

    if (leaderDoc) {
      // leader themselves
      myGroupAuthorIds.add(String(leaderDoc._id));

      // members tied to leaderId
      const groupMembersForLeader = await GroupMember.find({
        leaderId: leaderDoc._id,
      })
        .select('_id')
        .lean();

      if (!groupMembersForLeader.length && leaderDoc.groupName) {
        // fallback: same groupName
        const byGroupName = await GroupMember.find({
          groupName: leaderDoc.groupName,
        })
          .select('_id')
          .lean();
        byGroupName.forEach((m) => myGroupAuthorIds.add(String(m._id)));
      } else {
        groupMembersForLeader.forEach((m) => myGroupAuthorIds.add(String(m._id)));
      }
    } else if (groupMemberDoc) {
      // group member + their leader + peers
      if (groupMemberDoc.leaderId) {
        myGroupAuthorIds.add(String(groupMemberDoc.leaderId));
      }
      myGroupAuthorIds.add(String(groupMemberDoc._id));

      const peers = await GroupMember.find(
        groupMemberDoc.leaderId
          ? { leaderId: groupMemberDoc.leaderId }
          : groupMemberDoc.groupName
          ? { groupName: groupMemberDoc.groupName }
          : { _id: null }
      )
        .select('_id')
        .lean();

      peers.forEach((p) => myGroupAuthorIds.add(String(p._id)));
    }

    // Build an organization key for the current viewer
    const me = leaderDoc || groupMemberDoc || memberDoc || {};
    const myOrgKey =
      normalize(me.organizationId) ||
      normalize(me.organization) ||
      emailDomain(me.email);

    // Cache for author org keys
    const authorOrgKeyCache = new Map();

    async function getAuthorOrgKey(authorId) {
      const key = String(authorId);
      if (authorOrgKeyCache.has(key)) return authorOrgKeyCache.get(key);

      let aLeader = null,
        aGM = null,
        aMember = null;
      try {
        aLeader = await Leader.findById(authorId)
          .select('organizationId organization email')
          .lean();
        if (!aLeader)
          aGM = await GroupMember.findById(authorId)
            .select('organizationId organization email')
            .lean();
        if (!aLeader && !aGM)
          aMember = await Member.findById(authorId)
            .select('organizationId organization email')
            .lean();
      } catch (_) {
        // ignore
      }

      const doc = aLeader || aGM || aMember || {};
      const orgKey =
        normalize(doc.organizationId) ||
        normalize(doc.organization) ||
        emailDomain(doc.email) ||
        null;

      authorOrgKeyCache.set(key, orgKey);
      return orgKey;
    }

    // 1) missions I created
    const myMissions = missions.filter(
      (m) => userId && m.authorId && String(m.authorId) === String(userId)
    );

    // 2) missions created by my team
    const groupMissions = missions.filter((m) =>
      m.authorId ? myGroupAuthorIds.has(String(m.authorId)) : false
    );

    // 3) missions created by my organization (visibility allows it)
    let orgMissions = [];
    if (myOrgKey) {
      const uniqAuthorIds = [
        ...new Set(
          missions
            .map((m) => (m.authorId ? String(m.authorId) : null))
            .filter(Boolean)
        ),
      ];

      const orgKeyMap = new Map();
      for (const aid of uniqAuthorIds) {
        orgKeyMap.set(aid, await getAuthorOrgKey(aid));
      }

      orgMissions = missions.filter((m) => {
        const vis = m.visibility || 'all_members';
        if (!['organization_only', 'all_members'].includes(vis)) return false;

        const authorOrgKey = orgKeyMap.get(String(m.authorId));
        return !!authorOrgKey && authorOrgKey === myOrgKey;
      });
    } else {
      // if user has no org context, only show strictly org-only if you want
      orgMissions = missions.filter((m) => m.visibility === 'organization_only');
    }

    // 4) Twennie missions (globally visible)
    const twennieMissions = missions.filter(
      (m) => (m.visibility || 'all_members') === 'all_members'
    );

    // ---- END: segmentation ----

    // ---- BEGIN: enrich missions with creator + membership flags ----

    const creatorMetaCache = new Map();

    async function getCreatorMeta(authorId) {
      const key = String(authorId);
      if (creatorMetaCache.has(key)) return creatorMetaCache.get(key);

      const meta = await resolveCreatorById(authorId);
      creatorMetaCache.set(key, meta);
      return meta;
    }

    async function enrichList(list) {
      const result = [];
      for (const m of list) {
        let creatorName = 'Unknown Creator';
        let creatorImage = '/images/default-avatar.png';

        if (m.authorId) {
          const meta = await getCreatorMeta(m.authorId);
          creatorName = meta.name;
          creatorImage = meta.image;
        }

        result.push({
          ...m,
          creatorName,
          creatorImage,
          // membership flags for views (mirroring bytopic injection)
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

    // ---- END: enrich missions ----

    const sectionedMissions = [
      {
        sectionTitle: 'missions I created',
        missions: myMissionsEnriched,
        emptyMessage:
          'When you create missions, the ones you authored will show here. Use your missions to guide your own focus during light workloads.',
      },
      {
        sectionTitle: 'missions created by my team',
        missions: groupMissionsEnriched,
        emptyMessage:
          "Once your group starts creating missions, you'll see them here. Use team missions to coordinate how your group spends slow periods.",
      },
      {
        sectionTitle: "missions created by my organization",
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
    ];

    return res.render(viewName, {
      layout: 'unitviewlayout',
      title: pageTitle,
      shortSummary,
      longSummary,
      sectionedMissions,
      // root-level flags if you ever want @root.loggedIn etc.
      loggedIn,
      isLeaderOrGroupMember: leaderOrGroup,
      isPaid,
      isFree,
    });
  } catch (err) {
    console.error('[' + category + ' missions] error:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading missions.',
    });
  }
}

// Helper: build mission data from form body
function buildMissionDataFromBody(req) {
  return {
    // CORE STATUS / VISIBILITY
    status: req.body.status || 'one time mission',
    visibility: req.body.visibility || 'organization_only',

    // TITLES + CORE NARRATIVE
    mission_title: req.body.mission_title,
    purpose: req.body.purpose,
    why_it_matters: req.body.why_it_matters,
    background: req.body.background || '',

    // ✅ NEW: SUMMARIES FOR CARDS
    short_purpose: req.body.short_purpose || '',
    full_summary: req.body.full_summary || '',

    // DETAILS
    department_requesting: req.body.department_requesting || '',
    open_to: req.body.open_to || '',
    timeframe: req.body.timeframe || '',
    estimated_effort_hours: req.body.estimated_effort_hours || null,
    job_number: req.body.job_number || '',
    budget_amount: req.body.budget_amount || '',
    due_date: req.body.due_date || null,

    // APPROVALS / TASKS / CONTACTS / CHECKLIST
    approvals_required: req.body.approvals_required || [],
    task_instructions: req.body.task_instructions || [],
    contacts: req.body.contacts || [],
    deliverables_checklist: Array.isArray(req.body.deliverables_checklist)
      ? req.body.deliverables_checklist
      : (req.body.deliverables_checklist
          ? String(req.body.deliverables_checklist).split('\n').map(s => s.trim()).filter(Boolean)
          : []),

    // TOPIC + CATEGORY
    main_topic: req.body.main_topic || 'When the Workload is Light',
    category: req.body.category || 'internal_improvement',
  };
}



module.exports = {
  // Mission Control unchanged...
  missionControl: async (req, res) => {
    try {
      if (!isPaidMember(req)) {
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

      if (!isPaidMember(req)) {
        return res.status(403).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Access Restricted',
          errorMessage: 'Missions are available to paid members only.',
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


