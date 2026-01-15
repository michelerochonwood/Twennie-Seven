// controllers/orgadminController.js
// Org Admin Controller (Admin Mode only)
// Renders the SAME leader_dashboard view, but with adminMode=true so the view
// shows admin tabs/content and hides leader tabs/content.

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization');
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');

const GroupProfile = require('../models/profile_models/group_profile');

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

/**
 * Build a snapshot of organization totals + pending join requests.
 * (Learning footprint is stubbed for now.)
 */
async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  if (!organization) {
    return {
      organization: null,
      counts: {
        leaders: 0,
        groups: 0,
        members: 0,
        pendingJoinRequests: 0,
        pendingLibrarySubmissions: 0
      },
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

  const [
    leadersCount,
    distinctGroupNames,
    membersAgg,
    pendingJoinRequestsList
  ] = await Promise.all([
    Leader.countDocuments(leaderFilter),

    Leader.distinct('groupName', leaderFilter),

    Leader.aggregate([
      { $match: leaderFilter },
      { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
      { $group: { _id: null, total: { $sum: '$memberCount' } } }
    ]),

    OrganizationJoinRequest.find({
      organization: orgId,
      status: 'pending'
    })
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

/**
 * Build a list of org groups/leaders for admin listing.
 * Here, a "group" is effectively a Leader record (your current data model).
 */
async function buildOrgGroupsLeaders(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leaders = await Leader.find(leaderFilter)
    .select('_id groupLeaderName groupName groupImage profileImage members')
    .sort({ groupName: 1 })
    .lean();

  return (leaders || []).map(l => ({
    _id: l._id, // group id proxy = leader id
    groupName: l.groupName || 'Unnamed group',
    groupImage: l.groupImage || null,
    memberCount: Array.isArray(l.members) ? l.members.length : 0,

    groupLeaderName: l.groupLeaderName || '—',
    leaderId: l._id,
    leaderImage: l.profileImage || null
  }));
}

function baseRenderData(req) {
  return {
    layout: 'dashboardlayout',
    title: 'Leader Dashboard',

    // drives admin-mode UI
    adminMode: true,

    // your view checks leader.isAdmin
    leader: req.user,

    // keep CSRF available for admin forms
    csrfToken: req.csrfToken ? req.csrfToken() : null
  };
}

const orgadminController = {
  // ADMIN: My Organization snapshot
  async myOrganization(req, res, next) {
    try {
      const orgId = toObjectId(req.user?.organization);
      if (!orgId) return res.redirect('/dashboard/leader');

      const snapshot = await buildOrgSnapshot(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'my-organization',
        organization: snapshot.organization,
        counts: snapshot.counts,
        learningFootprint: snapshot.learningFootprint,
        pendingJoinRequestsList: snapshot.pendingJoinRequestsList
      });
    } catch (err) {
      console.error('Org admin myOrganization error:', err);
      return next(err);
    }
  },

  // ADMIN: Groups & Leaders listing
  async groupsLeaders(req, res, next) {
    try {
      const orgId = toObjectId(req.user?.organization);
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
    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect('/dashboard/leader/admin?msg=req-not-found');
      if (jr.status !== 'pending') return res.redirect('/dashboard/leader/admin?msg=req-not-pending');

      const leader = await Leader.findById(jr.leader);
      if (!leader) return res.redirect('/dashboard/leader/admin?msg=leader-not-found');

      // Attach org to leader
      leader.organization = jr.organization;
      leader.organizationOptOut = false;

      const org = await Organization.findById(jr.organization).select('name').lean();
      if (org?.name) leader.organizationName = org.name;

      await leader.save();

      // Keep group profile in sync (best-effort)
      await GroupProfile.updateOne(
        { groupId: leader._id },
        { $set: { organization: jr.organization } }
      );

      // Mark request approved
      jr.status = 'approved';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect('/dashboard/leader/admin?msg=approved');
    } catch (err) {
      console.error('approveJoinRequest error:', err);
      return res.redirect('/dashboard/leader/admin?msg=approve-error');
    }
  },

  // ADMIN: Reject a join request
  async rejectJoinRequest(req, res) {
    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect('/dashboard/leader/admin?msg=req-not-found');
      if (jr.status !== 'pending') return res.redirect('/dashboard/leader/admin?msg=req-not-pending');

      jr.status = 'rejected';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect('/dashboard/leader/admin?msg=rejected');
    } catch (err) {
      console.error('rejectJoinRequest error:', err);
      return res.redirect('/dashboard/leader/admin?msg=reject-error');
    }
  },

  // The remaining admin tabs can render without extra data for now
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


