// controllers/orgadminController.js
// Org Admin Controller (Admin Mode only)
// Renders the SAME leader_dashboard view, but with adminMode=true so the view
// shows admin tabs/content and hides leader tabs/content.

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization');

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

async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  if (!organization) {
    return {
      organization: null,
      counts: { leaders: 0, groups: 0, members: 0, pendingJoinRequests: 0, pendingLibrarySubmissions: 0 },
      learningFootprint: { activeLearners: 0, unitsCompleted: 0, promptSetsCompleted: 0, avgCompletionsPerLearner: 0, topUnitType: '—' },
    };
  }

  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leadersCount = await Leader.countDocuments(leaderFilter);

  const distinctGroupNames = await Leader.distinct('groupName', leaderFilter);
  const groupsCount = (distinctGroupNames || []).filter(n => String(n || '').trim().length).length;

  const membersAgg = await Leader.aggregate([
    { $match: leaderFilter },
    { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
    { $group: { _id: null, total: { $sum: '$memberCount' } } }
  ]);
  const membersCount = membersAgg?.[0]?.total || 0;

  return {
    organization,
    counts: {
      leaders: safeNumber(leadersCount),
      groups: safeNumber(groupsCount),
      members: safeNumber(membersCount),
      pendingJoinRequests: 0,
      pendingLibrarySubmissions: 0
    },
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
  .select('_id name groupName groupImage profileImage members')
  .sort({ groupName: 1 })
  .lean();


  return (leaders || []).map(l => ({
    _id: l._id,                               // group id (proxy = leader id)
    groupName: l.groupName || 'Unnamed group',
    groupImage: l.groupImage || null,
    memberCount: Array.isArray(l.members) ? l.members.length : 0,

    groupLeaderName: l.name || '—',
    leaderId: l._id,
    leaderImage: l.profileImage || null       // if your Leader uses another field, swap it here
  }));
}


function baseRenderData(req) {
  return {
    layout: 'dashboardlayout',
    title: 'Leader Dashboard',

    // ✅ this drives the mode switch + hides leader tabs/content
    adminMode: true,

    // used by the view (toggle + admin permission check)
    leader: req.user,

    // helpful, but your view is now driven by leader.isAdmin anyway
    isOrgAdmin: true,

    // keep CSRF available for any admin forms
    csrfToken: req.csrfToken ? req.csrfToken() : null
  };
}

const orgadminController = {

  async myOrganization(req, res, next) {
    try {
      const orgId = toObjectId(req.user?.organization);
      if (!orgId) return res.redirect('/dashboard/leader');

      const { organization, counts, learningFootprint } = await buildOrgSnapshot(orgId);

      return res.render('leader_dashboard', {
        ...baseRenderData(req),
        adminTab: 'my-organization',
        organization,
        counts,
        learningFootprint
      });
    } catch (err) {
      console.error('Org admin myOrganization error:', err);
      return next(err);
    }
  },

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

