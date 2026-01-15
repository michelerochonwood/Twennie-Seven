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

  if (!admin?.organization || admin.organizationOptOut === true) return null;
  return toObjectId(admin.organization);
}

// -----------------------------
// Snapshot builders
// -----------------------------
async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  // Base empty shape (keeps your view stable)
  const empty = {
    organization: null,
    counts: { leaders: 0, groups: 0, members: 0, pendingJoinRequests: 0, pendingLibrarySubmissions: 0 },
    pendingJoinRequestsList: [],
    learningFootprint: {
      activeLearners: 0,
      unitsCompleted: 0,
      promptSetsCompleted: 0,
      avgCompletionsPerLearner: 0,
      topUnitType: '—'
    }
  };

  if (!organization) return empty;

  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const [
    leadersCount,
    distinctGroupNames,
    membersAgg,
    pendingJoinRequestsList,
    learningFootprint
  ] = await Promise.all([
    // Leaders in org
    Leader.countDocuments(leaderFilter),

    // Group names in org
    Leader.distinct('groupName', leaderFilter),

    // Members total (sum of each leader.members array length)
    Leader.aggregate([
      { $match: leaderFilter },
      { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
      { $group: { _id: null, total: { $sum: '$memberCount' } } }
    ]),

    // Pending join requests
    OrganizationJoinRequest.find({ organization: orgId, status: 'pending' })
      .populate('leader', 'groupLeaderName groupLeaderEmail username groupName profileImage')
      .sort({ requestedAt: -1 })
      .lean(),

    // Learning footprint (Notes + PromptSetCompletion)
    // IMPORTANT: ensure buildLearningFootprintForOrg() matches your schema:
    // Notes uses memberID (not member) in your DB.
    buildLearningFootprintForOrg(orgId, 30)
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
      pendingJoinRequests: safeNumber(pendingJoinRequestsList?.length || 0),
      pendingLibrarySubmissions: 0
    },
    pendingJoinRequestsList: pendingJoinRequestsList || [],
    learningFootprint: learningFootprint || empty.learningFootprint
  };
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
      leaders: 0, groups: 0, members: 0, pendingJoinRequests: 0, pendingLibrarySubmissions: 0
    },
    learningFootprint: orgSnapshot?.learningFootprint || {
      activeLearners: 0, unitsCompleted: 0, promptSetsCompleted: 0, avgCompletionsPerLearner: 0, topUnitType: '—'
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

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'suggestions',
        ...payload
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

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'company-library',
        ...payload
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

