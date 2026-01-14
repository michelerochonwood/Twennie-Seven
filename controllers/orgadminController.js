// controllers/leaderOrgAdminController.js

/**
 * Org Admin Controller
 * --------------------
 * Stub-only controller for org admin dashboard tabs.
 * All routes render the existing leader dashboard view
 * with an adminTab flag so the UI can switch content.
 */

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization'); // adjust path if your org model lives elsewhere


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

  // Leaders in org (exclude opted out just in case)
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leadersCount = await Leader.countDocuments(leaderFilter);

  // "Groups" — best-available proxy without a separate Group model:
  // count distinct groupName values among leaders in this org
  const distinctGroupNames = await Leader.distinct('groupName', leaderFilter);
  const groupsCount = distinctGroupNames?.filter(Boolean).length || 0;

  // Members count — sum lengths of leader.members arrays (no GroupMember model needed)
  const membersAgg = await Leader.aggregate([
    { $match: { ...leaderFilter, members: { $exists: true } } },
    { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
    { $group: { _id: null, total: { $sum: '$memberCount' } } }
  ]);

  const membersCount = membersAgg?.[0]?.total || 0;

  // Pending counts + learning footprint: stub to 0 until we wire models
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



const leaderOrgAdminController = {

async myOrganization(req, res, next) {
  try {
    const orgIdRaw = req.user?.organization;
    if (!orgIdRaw) {
      // should be prevented by requireOrgAdmin, but keep it safe
      return res.redirect('/dashboard/leader');
    }

    const orgId = new mongoose.Types.ObjectId(String(orgIdRaw));

    const { organization, counts, learningFootprint } = await buildOrgSnapshot(orgId);

    // Provide safe defaults so existing leader dashboard partials don’t crash
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'my-organization',

      // ✅ admin_myorganization.hbs expects these:
      organization,
      counts,
      learningFootprint,

      // ✅ safe defaults for leader dashboard template references:
      leaderCounts: {},
      leaderBadges: {},
      registeredPromptSets: [],
      assignedPromptCards: [],
      csrfToken: req.csrfToken ? req.csrfToken() : null
    });
  } catch (err) {
    console.error('Org admin myOrganization error:', err);
    return next(err);
  }
},


  groupsLeaders(req, res) {
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'groups-leaders'
    });
  },

  requests(req, res) {
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'requests'
    });
  },

  suggestions(req, res) {
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'suggestions'
    });
  },

  companyLibrary(req, res) {
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'company-library'
    });
  },

  reports(req, res) {
    return res.render('dashboards/leader_dashboard', {
      leader: req.user,
      isOrgAdmin: true,
      adminTab: 'reports'
    });
  }

};

module.exports = leaderOrgAdminController;
