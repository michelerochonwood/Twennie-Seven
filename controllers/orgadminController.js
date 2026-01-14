// controllers/orgadminController.js

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
      counts: { leaders: 0, groups: 0, members: 0, pendingJoinRequests: 0, pendingLibrarySubmissions: 0 },
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

  const distinctGroupNames = await Leader.distinct('groupName', leaderFilter);
  const groupsCount = distinctGroupNames?.filter(Boolean).length || 0;

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
    pendingJoinRequests: 0,
    pendingLibrarySubmissions: 0
  };

  const learningFootprint = {
    activeLearners: 0,
    unitsCompleted: 0,
    promptSetsCompleted: 0,
    avgCompletionsPerLearner: 0,
    topUnitType: '—'
  };

  return { organization, counts, learningFootprint };
}

function baseRenderData(req) {
  return {
    layout: 'dashboardlayout',
    title: 'Leader Dashboard',
    leader: req.user,
    isOrgAdmin: true,
    leaderCounts: {},
    leaderBadges: {},
    registeredPromptSets: [],
    assignedPromptCards: [],
    csrfToken: req.csrfToken ? req.csrfToken() : null
  };
}

const leaderOrgAdminController = {

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

module.exports = leaderOrgAdminController;

