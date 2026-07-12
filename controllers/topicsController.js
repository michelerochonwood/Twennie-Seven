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
 * Choose a usable authenticated-user object.
 *
 * A usable object must contain:
 * - an ID
 * - a membership type/access level
 *
 * This prevents an incomplete res.locals.user object from
 * blocking a valid req.session.user object.
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
  if (!user) {
    console.log('ℹ️ Topics: no authenticated user found.');
    return null;
  }

  const userId =
    user._id ||
    user.id;

  const membershipType =
    user.membershipType ||
    user.accessLevel ||
    '';

  if (!userId) {
    console.log('⚠️ Topics: authenticated user has no ID.');
    return null;
  }

  console.log('🔎 Topics user:', {
    userId: String(userId),
    membershipType
  });

  /*
   * LEADER
   *
   * Leader → Organization
   */
  if (membershipType === 'leader') {
    const leader = await Leader.findById(userId)
      .select(
        'organization organizationOptOut isAdmin groupLeaderName'
      )
      .lean();

    if (!leader) {
      console.log('⚠️ Topics: leader record not found.');
      return null;
    }

    console.log('🔎 Topics leader:', {
      leaderId: String(leader._id),
      organization:
        leader.organization
          ? String(leader.organization)
          : null,
      organizationOptOut:
        leader.organizationOptOut
    });

    if (
      !leader.organization ||
      leader.organizationOptOut === true
    ) {
      return null;
    }

    const organization = await Organization.findById(
      leader.organization
    )
      .select('name topicVisibility')
      .lean();

    if (!organization) {
      console.log(
        '⚠️ Topics: organization record not found for leader.'
      );
      return null;
    }

    return organization;
  }

  /*
   * GROUP MEMBER
   *
   * GroupMember → Leader → Organization
   */
  if (membershipType === 'group_member') {
    const groupMember = await GroupMember.findById(userId)
      .select('leader name groupName')
      .lean();

    if (!groupMember) {
      console.log(
        '⚠️ Topics: group-member record not found.'
      );
      return null;
    }

    console.log('🔎 Topics group member:', {
      groupMemberId: String(groupMember._id),
      name: groupMember.name,
      leader:
        groupMember.leader
          ? String(groupMember.leader)
          : null
    });

    if (!groupMember.leader) {
      console.log(
        '⚠️ Topics: group member has no leader reference.'
      );
      return null;
    }

    const leader = await Leader.findById(
      groupMember.leader
    )
      .select(
        'organization organizationOptOut groupLeaderName'
      )
      .lean();

    if (!leader) {
      console.log(
        '⚠️ Topics: group member’s leader was not found.'
      );
      return null;
    }

    console.log('🔎 Topics member leader:', {
      leaderId: String(leader._id),
      leaderName: leader.groupLeaderName,
      organization:
        leader.organization
          ? String(leader.organization)
          : null,
      organizationOptOut:
        leader.organizationOptOut
    });

    if (
      !leader.organization ||
      leader.organizationOptOut === true
    ) {
      return null;
    }

    const organization = await Organization.findById(
      leader.organization
    )
      .select('name topicVisibility')
      .lean();

    if (!organization) {
      console.log(
        '⚠️ Topics: organization record not found for group-member leader.'
      );
      return null;
    }

    return organization;
  }

  console.log(
    `ℹ️ Topics: no organization rules for membership type "${membershipType}".`
  );

  return null;
}

const topicsController = {
  async showTopics(req, res, next) {
    try {
      const user = getCurrentUser(req, res);

      const organization =
        await getOrganizationForUser(user);

      const topicVisibility = organization
        ? normalizeTopicVisibility(
            organization.topicVisibility
          )
        : { ...DEFAULT_TOPIC_VISIBILITY };

      console.log('🎛️ Topics visibility:', {
        organization:
          organization?.name || null,
        topicVisibility
      });

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
        '❌ Error rendering topics page:',
        err
      );

      return next(err);
    }
  }
};

module.exports = topicsController;