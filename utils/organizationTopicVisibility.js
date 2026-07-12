// utils/organizationTopicVisibility.js

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
 * Select the first usable authenticated-user object.
 */
function getCurrentUser(req, res) {
  const candidates = [
    req.session?.user,
    req.user,
    res.locals.user
  ];

  return candidates.find(candidate => {
    if (!candidate) return false;

    const userId =
      candidate._id ||
      candidate.id;

    const membershipType =
      candidate.membershipType ||
      candidate.accessLevel;

    return Boolean(userId && membershipType);
  }) || null;
}

/**
 * Resolve the organization connected to a user.
 *
 * Leader:
 *   Leader → Organization
 *
 * Group member:
 *   GroupMember → Leader → Organization
 *
 * Individual members and visitors:
 *   no organization restrictions
 */
async function getOrganizationForUser(user) {
  if (!user) return null;

  const userId =
    user._id ||
    user.id;

  const membershipType =
    user.membershipType ||
    user.accessLevel ||
    '';

  if (!userId) {
    return null;
  }

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
      .select('leader')
      .lean();

    if (!groupMember?.leader) {
      return null;
    }

    const leader = await Leader.findById(groupMember.leader)
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

  return null;
}

/**
 * Return normalized organization topic visibility for a user.
 *
 * Users without an organization receive the unrestricted defaults.
 */
async function getTopicVisibilityForUser(user) {
  const organization =
    await getOrganizationForUser(user);

  if (!organization) {
    return {
      organization: null,
      topicVisibility: {
        ...DEFAULT_TOPIC_VISIBILITY
      }
    };
  }

  return {
    organization,
    topicVisibility: normalizeTopicVisibility(
      organization.topicVisibility
    )
  };
}

module.exports = {
  DEFAULT_TOPIC_VISIBILITY,
  normalizeTopicVisibility,
  getCurrentUser,
  getOrganizationForUser,
  getTopicVisibilityForUser
};