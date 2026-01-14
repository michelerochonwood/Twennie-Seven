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

  const leadersCount = await Leader.countDocuments(leaderFilter);

  // "Groups" proxy = distinct groupName among org leaders
  const distinctGroupNames = await Leader.distinct('groupName', leaderFilter);
  const groupsCount = distinctGroupNames?.filter(Boolean).length || 0;

  // Members count = sum of members array sizes across org leaders
  const membersAgg = await Leader.aggregate([
    { $match: { ...leaderFilter, members: { $exists: true } } },
    { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
    { $group: { _id: null, total: { $sum: '$memberCount' } } }
  ]);
  const membersCount = membersAgg?.[0]?.total || 0;

  const counts = {
    leaders: safeNumber(leadersCount),
    groups: safeNumber(groupsCount),
    members: safeNumber(membersCount),
    pendingJoinRequests: 0,        // wire later
    pendingLibrarySubmissions: 0   // wire later
  };

  const learningFootprint = {
    activeLearners: 0,             // wire later
    unitsCompleted: 0,             // wire later
    promptSetsCompleted: 0,        // wire later
    avgCompletionsPerLearner: 0,   // wire later
    topUnitType: '—'               // wire later
  };

  return { organization, counts, learningFootprint };
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
      const orgIdRaw = req.user?.organization;
      if (!orgIdRaw) return res.redirect('/dashboard/leader');

      const orgId = new mongoose.Types.ObjectId(String(orgIdRaw));
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

  groupsLeaders(req, res) {
    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'groups-leaders'
    });
  },

  requests(req, res) {
    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'requests'
    });
  },

  suggestions(req, res) {
    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'suggestions'
    });
  },

  companyLibrary(req, res) {
    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'company-library'
    });
  },

  reports(req, res) {
    return res.render('leader_dashboard', {
      ...baseRenderData(req),
      adminTab: 'reports'
    });
  }

};

module.exports = orgadminController;

