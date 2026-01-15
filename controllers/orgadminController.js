// controllers/orgadminController.js
// Org Admin Controller (Admin Mode only)
// Renders the SAME leader_dashboard view, but with adminMode=true so the view
// shows admin tabs/content and hides leader tabs/content.

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization');
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');
const GroupProfile = require('../models/profile_models/group_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');


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

  const admin = await Leader.findById(adminId).select('organization organizationOptOut isAdmin').lean();
  if (!admin?.organization || admin.organizationOptOut === true) return null;

  return toObjectId(admin.organization);
}

// -----------------------------
// Snapshot builders
// -----------------------------
async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  if (!organization) {
    return {
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
  }

  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const [leadersCount, distinctGroupNames, membersAgg, pendingJoinRequestsList] = await Promise.all([
    Leader.countDocuments(leaderFilter),

    Leader.distinct('groupName', leaderFilter),

    Leader.aggregate([
      { $match: leaderFilter },
      { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
      { $group: { _id: null, total: { $sum: '$memberCount' } } }
    ]),

    OrganizationJoinRequest.find({ organization: orgId, status: 'pending' })
      .populate('leader', 'groupLeaderName groupLeaderEmail username groupName profileImage')
      .sort({ requestedAt: -1 })
      .lean()
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
    learningFootprint: {
      activeLearners: 0,
      unitsCompleted: 0,
      promptSetsCompleted: 0,
      avgCompletionsPerLearner: 0,
      topUnitType: '—'
    }
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

  // Group images
  const groupProfiles = await GroupProfile.find({ groupId: { $in: ids } })
    .select('groupId groupImage')
    .lean();
  const groupImgByLeaderId = new Map(groupProfiles.map(p => [p.groupId.toString(), p.groupImage]));

  // Leader profile images (true “leader avatar”)
  const leaderProfiles = await LeaderProfile.find({ leaderId: { $in: ids } })
    .select('leaderId profileImage')
    .lean();
  const leaderImgByLeaderId = new Map(leaderProfiles.map(p => [p.leaderId.toString(), p.profileImage]));

  return leaders.map(l => {
    const idStr = l._id.toString();

    return {
      _id: l._id,
      groupName: l.groupName || 'Unnamed group',
      groupLeaderName: l.groupLeaderName || '—',

      leaderId: l._id,

      // ✅ leader avatar comes from LeaderProfile first
      leaderImage:
        leaderImgByLeaderId.get(idStr) ||
        l.profileImage ||
        '/images/default-avatar.png',

      // ✅ group avatar comes from GroupProfile
      groupImage:
        groupImgByLeaderId.get(idStr) ||
        '/images/default-group.png',

      memberCount: Array.isArray(l.members) ? l.members.length : (l.groupSize || 0)
    };
  });
}


// -----------------------------
// Controller
// -----------------------------
const orgadminController = {
  // ADMIN: My Organization snapshot
  async myOrganization(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const snapshot = await buildOrgSnapshot(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'my-organization',
        orgSnapshot: snapshot
      });
    } catch (err) {
      console.error('Org admin myOrganization error:', err);
      return next(err);
    }
  },

  // ADMIN: Groups & Leaders listing
  async groupsLeaders(req, res, next) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('/dashboard/leader');

      const organization = await Organization.findById(orgId).select('name slug').lean();
      const orgGroups = await buildOrgGroupsLeaders(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'groups-leaders',
        organization,
        orgGroups
      });
    } catch (err) {
      console.error('Org admin groupsLeaders error:', err);
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
  },

  // Remaining admin tabs
  requests(req, res) {
    return res.render('leader_dashboard', { ...baseRenderData(req), adminTab: 'requests' });
  },

  suggestions(req, res) {
    return res.render('leader_dashboard', { ...baseRenderData(req), adminTab: 'suggestions' });
  },

  companyLibrary(req, res) {
    return res.render('leader_dashboard', { ...baseRenderData(req), adminTab: 'company-library' });
  },

  reports(req, res) {
    return res.render('leader_dashboard', { ...baseRenderData(req), adminTab: 'reports' });
  }
};

module.exports = orgadminController;
