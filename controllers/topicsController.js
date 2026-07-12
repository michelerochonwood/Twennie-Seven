// controllers/topicsController.js

const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Organization = require('../models/member_models/organization');

const DEFAULT_TOPIC_VISIBILITY = Object.freeze({
  projectmanagement: true,
  businessdevelopmentandmarketing: true,
  proposals: true,
  peoplemanagement: true,
  workplaceculture: true,
  technology: true,
  ai: true
});

/**
 * Fail-open normalization:
 * - explicit false = closed
 * - true or missing = open
 */
function normalizeTopicVisibility(topicVisibility = {}) {
  return {
    projectmanagement:
      topicVisibility.projectmanagement !== false,

    businessdevelopmentandmarketing:
      topicVisibility.businessdevelopmentandmarketing !== false,

    proposals:
      topicVisibility.proposals !== false,

    peoplemanagement:
      topicVisibility.peoplemanagement !== false,

    workplaceculture:
      topicVisibility.workplaceculture !== false,

    technology:
      topicVisibility.technology !== false,

    ai:
      topicVisibility.ai !== false
  };
}

/**
 * Find the organization connected to the current learner.
 *
 * Leaders:
 *   organization is stored directly on the leader.
 *
 * Group members:
 *   organization is resolved through their group leader.
 *
 * Individual members and logged-out visitors:
 *   no organization restrictions.
 */
async function getOrganizationForUser(user) {
  if (!user) return null;

  const userId = user._id || user.id;
  if (!userId) return null;

  const membershipType =
    user.membershipType ||
    user.accessLevel ||
    '';

  if (membershipType === 'leader') {
    const leader = await Leader.findById(userId)
      .select('organization organizationOptOut')
      .lean();

    if (
      !leader?.organization ||
      leader.organizationOptOut === true
    ) {
      return null;
    }

    return Organization.findById(leader.organization)
      .select('name topicVisibility')
      .lean();
  }

if (membershipType === 'group_member') {
  const groupMember = await GroupMember.findById(userId)
    .select('organization')
    .lean();

  if (!groupMember?.organization) {
    return null;
  }

  return Organization.findById(groupMember.organization)
    .select('name topicVisibility')
    .lean();
}

  return null;
}

const topicsController = {
  async showTopics(req, res, next) {
    try {
      const user =
        res.locals.user ||
        req.user ||
        null;

      const organization =
        await getOrganizationForUser(user);

      const topicVisibility = organization
        ? normalizeTopicVisibility(
            organization.topicVisibility
          )
        : { ...DEFAULT_TOPIC_VISIBILITY };

      const topicSignals = [
        'Conducting Market Research',
        'Proposal Strategy',
        'Leadership in Technical Consulting',
        'Managing Scope So It Doesnt Manage You'
      ];

      return res.render('promo_views/topics', {
        layout: 'mainlayout',
        topicSignals,

        organization,
        topicVisibility,

        hasOrganizationRestrictions:
          Boolean(organization),

        organizationName:
          organization?.name || ''
      });
    } catch (err) {
      console.error(
        'Error rendering topics page:',
        err
      );

      return next(err);
    }
  }
};

module.exports = topicsController;