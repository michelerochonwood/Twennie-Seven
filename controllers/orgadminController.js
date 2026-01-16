// controllers/orgadminController.js
// Org Admin Controller (Admin Mode only)
// Renders the SAME leader_dashboard view, with adminMode=true.
// IMPORTANT: We preload ALL admin-mode data on every admin route render
// so admin tabs can switch client-side with no flash / missing data.

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization');
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');
const GroupProfile = require('../models/profile_models/group_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const Notes = require('../models/notes/notes');
const UnitSuggestion = require('../models/unit_models/unit_suggestion'); // optional if you pick suggestions metric
const Article   = require('../models/unit_models/article');
const Video     = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const Interview = require('../models/unit_models/interview');
const Exercise  = require('../models/unit_models/exercise');
const Template  = require('../models/unit_models/template');
const Mission   = require('../models/unit_models/mission');
const Nugget    = require('../models/unit_models/nugget');
const GroupMember = require('../models/member_models/group_member');
const Upcoming = require('../models/unit_models/upcoming');


// -----------------------------
// Helpers
// -----------------------------
function baseRenderData(req) {
  return {
    layout: 'dashboardlayout',
    title: 'Leader Dashboard',
    adminMode: true,
    leader: req.user,
    csrfToken: req.csrfToken ? req.csrfToken() : null
  };
}

function safeNumber(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v : 0;
}

function toObjectId(id) {
  if (!id) return null;
  if (id instanceof mongoose.Types.ObjectId) return id;
  const s = String(id);
  return mongoose.Types.ObjectId.isValid(s) ? new mongoose.Types.ObjectId(s) : null;
}

// Always prefer a fresh orgId from DB (avoid stale req.user.organization)
async function getOrgIdForAdmin(req) {
  const adminId = req.user?._id;
  if (!adminId) return null;

  const admin = await Leader.findById(adminId)
    .select('organization organizationOptOut isAdmin')
    .lean();

  if (!admin?.isAdmin) return null;
  if (!admin?.organization || admin.organizationOptOut === true) return null;

  return toObjectId(admin.organization);
}


function fmtDate(d) {
  if (!d) return '';
  const dd = new Date(d);
  if (Number.isNaN(dd.getTime())) return '';
  return dd.toLocaleDateString('en-CA', { year: 'numeric', month: 'short', day: '2-digit' });
}

function viewPathForUnit(unitType, unitId) {
  const t = String(unitType || '').toLowerCase();
  const id = unitId?.toString?.() || String(unitId || '');

  if (t === 'nugget')  return `/unitviews/nuggets/view/${id}`;
  if (t === 'mission') return `/unitviews/missions/view/${id}`;
  return `/unitviews/${t}s/view/${id}`;
}

function pickTitle(unit) {
  return (
    unit.mission_title ||
    unit.article_title ||
    unit.video_title ||
    unit.promptset_title ||
    unit.interview_title ||
    unit.exercise_title ||
    unit.template_title ||
    unit.title ||
    unit.name ||
    'Untitled Unit'
  );
}

function pickMainTopic(unit) {
  return unit.main_topic || unit.discipline || unit.client || unit.region || 'No topic';
}

function normalizeUnitTypeFromDoc(doc) {
  if (doc.article_title) return 'article';
  if (doc.video_title) return 'video';
  if (doc.promptset_title) return 'promptset';
  if (doc.interview_title) return 'interview';
  if (doc.exercise_title) return 'exercise';
  if (doc.template_title) return 'template';
  if (doc.mission_title) return 'mission';
  if (doc.title && (doc.discipline || doc.client || doc.region)) return 'nugget';
  return 'unknown';
}


async function buildLibrarySubmissionsCount(orgId) {
  // NOTE: this is now ALL-TIME (no date filter)

  // org people = leaders + their members
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };
  const leaders = await Leader.find(leaderFilter).select('_id members').lean();
  if (!leaders.length) return 0;

  const idSet = new Set();
  for (const l of leaders) {
    if (l?._id) idSet.add(String(l._id));
    if (Array.isArray(l.members)) {
      for (const m of l.members) idSet.add(String(m));
    }
  }

  const orgPersonIds = Array.from(idSet)
    .filter(s => mongoose.Types.ObjectId.isValid(s))
    .map(s => new mongoose.Types.ObjectId(s));

  if (!orgPersonIds.length) return 0;

  const [
    articlesCreated,
    videosCreated,
    promptSetsCreated,
    interviewsCreated,
    exercisesCreated,
    templatesCreated,
    missionsCreated,
    nuggetsCreated
  ] = await Promise.all([
    Article.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Video.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    PromptSet.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Interview.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Exercise.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Template.countDocuments({ 'author.id': { $in: orgPersonIds } }),

    // missions/nuggets use different creator fields in your app
    Mission.countDocuments({ created_by: { $in: orgPersonIds } }),
    Nugget.countDocuments({ createdBy: { $in: orgPersonIds } })
  ]);

  return (
    articlesCreated +
    videosCreated +
    promptSetsCreated +
    interviewsCreated +
    exercisesCreated +
    templatesCreated +
    missionsCreated +
    nuggetsCreated
  );
}


// -----------------------------
// Snapshot builders
// -----------------------------
async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  const empty = {
    organization: null,
    counts: {
      leaders: 0,
      groups: 0,
      members: 0,
      pendingJoinRequests: 0,
      pendingLibrarySubmissions: 0,
      suggestionsSent: 0
    },
    pendingJoinRequestsList: [],
    learningFootprint: {
      activeLearners: 0,
      unitsCompleted: 0,
      promptSetsCompleted: 0,
      avgCompletionsPerLearner: 0,
      mostPopularTopic: '—'
    }
  };

  if (!organization) return empty;

  const leaderFilter = {
    organization: orgId,
    organizationOptOut: { $ne: true }
  };

  const [
    leadersCount,
    distinctGroupNames,
    membersAgg,
    pendingJoinRequestsList,
    learningFootprint,
    suggestionsSent,
    pendingLibrarySubmissions
  ] = await Promise.all([
    // leaders
    Leader.countDocuments(leaderFilter),

    // groups (distinct group names)
    Leader.distinct('groupName', leaderFilter),

    // members (sum of leader.members[])
    Leader.aggregate([
      { $match: leaderFilter },
      {
        $project: {
          memberCount: { $size: { $ifNull: ['$members', []] } }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$memberCount' }
        }
      }
    ]),

    // join requests
    OrganizationJoinRequest.find({
      organization: orgId,
      status: 'pending'
    })
      .populate(
        'leader',
        'groupLeaderName groupLeaderEmail username groupName profileImage'
      )
      .sort({ requestedAt: -1 })
      .lean(),

    // learning footprint (30 days is fine here)
    buildLearningFootprintForOrg(orgId, 30),

    // ✅ ALL-TIME suggestions
UnitSuggestion.countDocuments({
  $or: [{ organization: orgId }, { organization: String(orgId) }]
}),

    // ✅ ALL-TIME library submissions
    buildLibrarySubmissionsCount(orgId)
  ]);

  const groupsCount = (distinctGroupNames || [])
    .map(n => String(n || '').trim())
    .filter(Boolean).length;

  const membersCount = membersAgg?.[0]?.total || 0;

  return {
    organization,
    counts: {
      leaders: safeNumber(leadersCount),
      groups: safeNumber(groupsCount),
      members: safeNumber(membersCount),
      pendingJoinRequests: safeNumber(pendingJoinRequestsList.length),
      pendingLibrarySubmissions: safeNumber(pendingLibrarySubmissions),
      suggestionsSent: safeNumber(suggestionsSent)
    },
    pendingJoinRequestsList,
    learningFootprint: learningFootprint || empty.learningFootprint
  };
}


async function buildOrgLeaderLibraries(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  // all leaders (groups) in org
  const leaders = await Leader.find(leaderFilter)
    .select('_id groupName groupLeaderName members groupSize')
    .sort({ groupName: 1 })
    .lean();

  if (!leaders.length) return [];

  const rows = [];

  for (const leader of leaders) {
    const leaderId = leader._id;
    const leaderIdStr = leaderId.toString();

    // group members for this leader
    const groupMembers = await GroupMember.find({ groupId: leaderId })
      .select('_id name')
      .lean();

    const groupMemberIds = groupMembers.map(m => m._id);
    const memberNameById = new Map(groupMembers.map(m => [m._id.toString(), m.name]));

    // ----- leader units (authored by leader) -----
    const [
      leaderArticles,
      leaderVideos,
      leaderPromptSets,
      leaderInterviews,
      leaderExercises,
      leaderTemplates,
      leaderUpcomings,
      leaderNuggets,
      leaderMissions
    ] = await Promise.all([
      Article.find({ 'author.id': leaderIdStr }).lean(),
      Video.find({ 'author.id': leaderIdStr }).lean(),
      PromptSet.find({ 'author.id': leaderIdStr }).lean(),
      Interview.find({ 'author.id': leaderIdStr }).lean(),
      Exercise.find({ 'author.id': leaderIdStr }).lean(),
      Template.find({ 'author.id': leaderIdStr }).lean(),
      Upcoming.find({ createdBy: leaderId }).lean(),
      Nugget.find({ createdBy: leaderId }).lean(),
      Mission.find({ $or: [{ created_by: leaderId }, { createdBy: leaderId }] }).lean()
    ]);

    const leaderUnits = [
      ...leaderArticles,
      ...leaderVideos,
      ...leaderPromptSets,
      ...leaderInterviews,
      ...leaderExercises,
      ...leaderTemplates,
      ...(leaderUpcomings || []),
      ...(leaderNuggets || []),
      ...(leaderMissions || [])
    ].map(u => {
      const unitType = u.unit_type ? 'upcoming' : normalizeUnitTypeFromDoc(u);
      return {
        unitType,
        plannedType: u.unit_type || null, // upcoming only
        title: pickTitle(u),
        status: u.status || (unitType === 'nugget' ? '—' : 'Unknown'),
        mainTopic: pickMainTopic(u),
        _id: u._id,
        projectedRelease: u.projected_release_at || u.projectedRelease || null
      };
    });

    // ----- group member units (authored by group members) -----
    const [
      gmArticles,
      gmVideos,
      gmPromptSets,
      gmInterviews,
      gmExercises,
      gmTemplates,
      gmUpcomings,
      gmNuggets,
      gmMissions
    ] = await Promise.all([
      Article.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Video.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      PromptSet.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Interview.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Exercise.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Template.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Upcoming.find({ createdBy: { $in: groupMemberIds } }).lean(),
      Nugget.find({ createdBy: { $in: groupMemberIds } }).lean(),
      Mission.find({ $or: [{ created_by: { $in: groupMemberIds } }, { createdBy: { $in: groupMemberIds } }] }).lean()
    ]);

    const groupMemberUnits = [
      ...gmArticles,
      ...gmVideos,
      ...gmPromptSets,
      ...gmInterviews,
      ...gmExercises,
      ...gmTemplates,
      ...(gmUpcomings || []),
      ...(gmNuggets || []),
      ...(gmMissions || [])
    ].map(u => {
      const unitType = u.unit_type ? 'upcoming' : normalizeUnitTypeFromDoc(u);
      const authorId = (u.createdBy || u.author?.id || u.author || u.created_by || '').toString?.() || '';

      return {
        author: memberNameById.get(authorId) || 'Group Member',
        unitType,
        plannedType: u.unit_type || null, // upcoming only
        title: pickTitle(u),
        status: u.status || (unitType === 'nugget' ? '—' : 'Unknown'),
        mainTopic: pickMainTopic(u),
        _id: u._id,
        projectedRelease: u.projected_release_at || u.projectedRelease || null
      };
    });

    rows.push({
      leaderId: leaderIdStr,
      leaderName: leader.groupLeaderName || leader.username || 'Leader',
      groupName: leader.groupName || 'Unnamed group',
      leaderUnits,
      groupMemberUnits
    });
  }

  return rows;
}


function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

/**
 * Learning footprint (last N days) for an organization.
 * Assumes:
 * - Non-prompt units are "completed" when a Notes doc is created.
 * - Prompt sets are "completed" when a PromptSetCompletion doc indicates completion.
 *
 * IMPORTANT: This computes footprint for users currently in org (leaders + their members).
 * If you truly want "from this point forward" only, this is already essentially that,
 * because it only looks back 30 days.
 */
async function buildLearningFootprintForOrg(orgId, days = 30) {
  const since = daysAgo(days);

  const empty = {
    activeLearners: 0,
    unitsCompleted: 0,
    promptSetsCompleted: 0,
    avgCompletionsPerLearner: 0,
    mostPopularTopic: '—'
  };

  // leaders in org
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };
  const leaders = await Leader.find(leaderFilter).select('_id members').lean();

  if (!leaders.length) return empty;

  // Build learner ids: leaders + their members
  const learnerIdSet = new Set();
  for (const l of leaders) {
    if (l?._id) learnerIdSet.add(String(l._id));
    if (Array.isArray(l.members)) {
      for (const m of l.members) learnerIdSet.add(String(m));
    }
  }

  const learnerIds = Array.from(learnerIdSet)
    .filter(s => mongoose.Types.ObjectId.isValid(s))
    .map(s => new mongoose.Types.ObjectId(s));

  if (!learnerIds.length) return empty;

  // Notes completions (non-prompt units) + most popular topic from Notes.main_topic
  const notesAgg = await Notes.aggregate([
    {
      $match: {
        createdAt: { $gte: since },
        memberID: { $in: learnerIds }
      }
    },
    {
      $project: {
        memberID: 1,
        main_topic: { $trim: { input: { $ifNull: ['$main_topic', ''] } } }
      }
    },
    {
      $facet: {
        // totals + active learners
        totals: [
          {
            $group: {
              _id: null,
              unitsCompleted: { $sum: 1 },
              activeLearnerSet: { $addToSet: '$memberID' }
            }
          }
        ],

        // most popular topic (ignore blanks)
        topTopic: [
          { $match: { main_topic: { $ne: '' } } },
          { $group: { _id: '$main_topic', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 1 }
        ]
      }
    }
  ]);

  const totals = notesAgg?.[0]?.totals?.[0] || null;
  const unitsCompleted = totals?.unitsCompleted || 0;

  const activeFromNotesArr = totals?.activeLearnerSet || [];
  const activeFromNotes = new Set(activeFromNotesArr.map(id => String(id)));

  const mostPopularTopic =
    notesAgg?.[0]?.topTopic?.[0]?._id ? String(notesAgg[0].topTopic[0]._id) : '—';

  // Prompt set completions
  const pscAgg = await PromptSetCompletion.aggregate([
    {
      $match: {
        completedAt: { $gte: since },
        memberId: { $in: learnerIds }
      }
    },
    {
      $group: {
        _id: null,
        promptSetsCompleted: { $sum: 1 },
        activeLearnerSet: { $addToSet: '$memberId' }
      }
    }
  ]);

  const promptSetsCompleted = pscAgg?.[0]?.promptSetsCompleted || 0;
  const activeFromPSCArr = pscAgg?.[0]?.activeLearnerSet || [];
  const activeFromPSC = new Set(activeFromPSCArr.map(id => String(id)));

  // Union active learners (notes OR prompt sets)
  const activeLearners = new Set([...activeFromNotes, ...activeFromPSC]).size;

  const avgCompletionsPerLearner =
    activeLearners > 0 ? Number((unitsCompleted / activeLearners).toFixed(2)) : 0;

  return {
    activeLearners: safeNumber(activeLearners),
    unitsCompleted: safeNumber(unitsCompleted),
    promptSetsCompleted: safeNumber(promptSetsCompleted),
    avgCompletionsPerLearner,
    mostPopularTopic
  };
}



async function buildOrgGroupsLeaders(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leaders = await Leader.find(leaderFilter)
    .select('_id groupLeaderName groupName profileImage members groupSize')
    .sort({ groupName: 1 })
    .lean();

  if (!leaders.length) return [];

  const ids = leaders.map(l => l._id);

  const [groupProfiles, leaderProfiles] = await Promise.all([
    // Group images
    GroupProfile.find({ groupId: { $in: ids } })
      .select('groupId groupImage')
      .lean(),

    // Leader profile images (true “leader avatar”)
    LeaderProfile.find({ leaderId: { $in: ids } })
      .select('leaderId profileImage')
      .lean()
  ]);

  const groupImgByLeaderId = new Map(groupProfiles.map(p => [p.groupId.toString(), p.groupImage]));
  const leaderImgByLeaderId = new Map(leaderProfiles.map(p => [p.leaderId.toString(), p.profileImage]));

  return leaders.map(l => {
    const idStr = l._id.toString();

    return {
      _id: l._id,
      groupName: l.groupName || 'Unnamed group',
      groupLeaderName: l.groupLeaderName || '—',
      leaderId: l._id,

      leaderImage:
        leaderImgByLeaderId.get(idStr) ||
        l.profileImage ||
        '/images/default-avatar.png',

      groupImage:
        groupImgByLeaderId.get(idStr) ||
        '/images/default-group.png',

      memberCount: Array.isArray(l.members) ? l.members.length : (l.groupSize || 0)
    };
  });
}

// Build all data needed for ALL admin tabs, every time (no flash, no missing vars)
async function buildAdminPayload(orgId) {
  const [orgSnapshot, orgGroups, organization] = await Promise.all([
    buildOrgSnapshot(orgId),
    buildOrgGroupsLeaders(orgId),
    Organization.findById(orgId).select('name slug industry createdAt').lean()
  ]);

  return {
    // keep snapshot available if some partials use orgSnapshot.*
    orgSnapshot,

    // ✅ flatten for existing partials like admin_myorganization
counts: orgSnapshot?.counts || {
  leaders: 0, groups: 0, members: 0,
  pendingJoinRequests: 0,
  pendingLibrarySubmissions: 0,
  suggestionsSent: 0
},
learningFootprint: orgSnapshot?.learningFootprint || {
  activeLearners: 0,
  unitsCompleted: 0,
  promptSetsCompleted: 0,
  avgCompletionsPerLearner: 0,
  mostPopularTopic: '—'
},
    pendingJoinRequestsList: orgSnapshot?.pendingJoinRequestsList || [],

    // org identity + other admin tab data
    organization,
    orgGroups
  };
}


// -----------------------------
// Controller
// -----------------------------
const orgadminController = {
  async myOrganization(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const payload = await buildAdminPayload(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'my-organization',
        ...payload
      });
    } catch (err) {
      console.error('Org admin myOrganization error:', err);
      return next(err);
    }
  },

  async groupsLeaders(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const payload = await buildAdminPayload(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'groups-leaders',
        ...payload
      });
    } catch (err) {
      console.error('Org admin groupsLeaders error:', err);
      return next(err);
    }
  },

  async requests(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const payload = await buildAdminPayload(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'requests',
        ...payload
      });
    } catch (err) {
      console.error('Org admin requests error:', err);
      return next(err);
    }
  },

async suggestions(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const payload = await buildAdminPayload(orgId);

    const adminId = req.user?._id;
    if (!adminId) return res.redirect('/dashboard/leader');

    // ✅ My Suggestions (created by this admin, within this org)
    const rawMySuggestions = await UnitSuggestion.find({
      organization: orgId,
      suggestedBy: adminId
    })
      .sort({ createdAt: -1 })
      .lean();

    // Resolve leader recipient names in one query
    const leaderIds = [...new Set(
      rawMySuggestions
        .map(s => s.leaderId?.toString?.())
        .filter(Boolean)
    )];

    const leaders = leaderIds.length
      ? await Leader.find({ _id: { $in: leaderIds } })
          .select('_id groupLeaderName username groupName')
          .lean()
      : [];

    const leaderNameById = new Map(
      leaders.map(l => [
        l._id.toString(),
        (l.groupLeaderName || l.username || l.groupName || 'Leader')
      ])
    );

    const mySuggestions = rawMySuggestions.map(s => {
      const leaderIdStr = s.leaderId?.toString?.() || '';
      const leaderName = leaderIdStr ? (leaderNameById.get(leaderIdStr) || 'Leader') : '';

      return {
        _id: s._id.toString(),
        unitType: s.unitType,
        unitTitle: s.unitTitle || 'Untitled unit',
        main_topic: s.main_topic || '',
        secondary_topic: s.secondary_topic || '',
        note: s.note || '',
        status: s.status || 'pending',
        suggestedAtFormatted: s.createdAt ? fmtDate(s.createdAt) : '',
        viewPath: viewPathForUnit(s.unitType, s.unitId),

        // ✅ for the partial (array for future multi-leader support)
        leaderId: leaderIdStr,
        suggestedToNames: leaderName ? [leaderName] : []
      };
    });

    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'suggestions',
      ...payload,
      mySuggestions
    });
  } catch (err) {
    console.error('Org admin suggestions error:', err);
    return next(err);
  }
},



async companyLibrary(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const payload = await buildAdminPayload(orgId);

    // ✅ NEW: libraries for every leader + their group
    const orgLeaderLibraries = await buildOrgLeaderLibraries(orgId);

    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'company-library',
      ...payload,
      orgLeaderLibraries
    });
  } catch (err) {
    console.error('Org admin companyLibrary error:', err);
    return next(err);
  }
},


  async reports(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const payload = await buildAdminPayload(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'reports',
        ...payload
      });
    } catch (err) {
      console.error('Org admin reports error:', err);
      return next(err);
    }
  },

  // ADMIN: Approve a join request
  async approveJoinRequest(req, res) {
    const back = '/dashboard/leader/org-admin/my-organization';

    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect(`${back}?msg=req-not-found`);
      if (jr.status !== 'pending') return res.redirect(`${back}?msg=req-not-pending`);

      const leader = await Leader.findById(jr.leader);
      if (!leader) return res.redirect(`${back}?msg=leader-not-found`);

      leader.organization = jr.organization;
      leader.organizationOptOut = false;

      const org = await Organization.findById(jr.organization).select('name').lean();
      if (org?.name) leader.organizationName = org.name;

      await leader.save();

      await GroupProfile.updateOne(
        { groupId: leader._id },
        { $set: { organization: jr.organization } }
      );

      jr.status = 'approved';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect(`${back}?msg=approved`);
    } catch (err) {
      console.error('approveJoinRequest error:', err);
      return res.redirect(`${back}?msg=approve-error`);
    }
  },

  // ADMIN: Reject a join request
  async rejectJoinRequest(req, res) {
    const back = '/dashboard/leader/org-admin/my-organization';

    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect(`${back}?msg=req-not-found`);
      if (jr.status !== 'pending') return res.redirect(`${back}?msg=req-not-pending`);

      jr.status = 'rejected';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect(`${back}?msg=rejected`);
    } catch (err) {
      console.error('rejectJoinRequest error:', err);
      return res.redirect(`${back}?msg=reject-error`);
    }
  }
};

module.exports = orgadminController;

