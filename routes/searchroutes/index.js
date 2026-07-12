// routes/searchroutes/index.js

const express = require('express');
const router = express.Router();

const Article = require('../../models/unit_models/article');
const Video = require('../../models/unit_models/video');
const Interview = require('../../models/unit_models/interview');
const PromptSet = require('../../models/unit_models/promptset');
const Exercise = require('../../models/unit_models/exercise');
const Template = require('../../models/unit_models/template');
const Nugget = require('../../models/unit_models/nugget');
const Mission = require('../../models/unit_models/mission');

const ensureAuthenticated =
  require('../../middleware/ensureAuthenticated');

const {
  getCurrentUser,
  getTopicVisibilityForUser
} = require('../../utils/organizationTopicVisibility');

const {
  isUnitVisibleByTopic
} = require('../../utils/unitTopicVisibility');

/**
 * Build the existing library-level visibility filter.
 *
 * This handles:
 * - units visible to all members
 * - organization-only units
 * - team-only units
 *
 * Organization topic restrictions are handled separately after
 * the database queries return.
 */
function buildVisibilityFilter({
  organizationId = null,
  teams = []
} = {}) {
  const orConditions = [
    {
      visibility: 'all_members'
    }
  ];

  if (organizationId) {
    orConditions.push({
      visibility: 'organization_only',
      organization: organizationId
    });
  }

  if (Array.isArray(teams) && teams.length > 0) {
    orConditions.push({
      visibility: 'team_only',
      team: {
        $in: teams
      }
    });
  }

  return {
    $or: orConditions
  };
}

/**
 * Retrieve team references from whichever authenticated-user
 * object contains them.
 *
 * Session users may contain only an ID and membership type,
 * while req.user or res.locals.user may contain additional data.
 */
function getUserTeams(req, res) {
  const candidates = [
    req.user,
    res.locals.user,
    req.session?.user
  ];

  for (const candidate of candidates) {
    if (
      candidate &&
      Array.isArray(candidate.teams) &&
      candidate.teams.length > 0
    ) {
      return candidate.teams;
    }
  }

  return [];
}

/**
 * Filter a collection of units using the organization's
 * individual-topic access settings.
 *
 * Unmapped units remain visible.
 */
function filterUnitsByTopic(units, topicVisibility) {
  if (!Array.isArray(units)) {
    return [];
  }

  return units.filter(unit =>
    isUnitVisibleByTopic(
      unit,
      topicVisibility
    )
  );
}

/**
 * GET /search/library-units?q=keyword
 *
 * Searches all supported unit collections and removes units
 * associated only with topics disabled by the user's organization.
 */
router.get(
  '/library-units',
  ensureAuthenticated,
  async (req, res) => {
    try {
      const q =
        (req.query.q || '').trim();

      if (q.length < 2) {
        return res.json([]);
      }

      /*
       * Resolve the authenticated user consistently.
       *
       * This supports:
       * - req.session.user
       * - req.user
       * - res.locals.user
       */
      const user =
        getCurrentUser(req, res);

      /*
       * Resolve:
       * - the user's organization
       * - the organization's topic visibility settings
       *
       * Group members are resolved through:
       * GroupMember → Leader → Organization
       */
      const {
        organization,
        topicVisibility
      } = await getTopicVisibilityForUser(user);

      const organizationId =
        organization?._id || null;

      const teams =
        getUserTeams(req, res);

      /*
       * Existing document-level visibility:
       * all members, organization-only, and team-only.
       */
      const visibilityFilter =
        buildVisibilityFilter({
          organizationId,
          teams
        });

      /*
       * Escape the search text before creating a regular expression.
       *
       * This prevents characters such as *, +, ?, (, and [
       * from being treated as regular-expression instructions.
       */
      const escapedQuery =
        q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      const regex =
        new RegExp(escapedQuery, 'i');

      const [
        articles,
        videos,
        interviews,
        promptsets,
        exercises,
        templates,
        nuggets,
        missions
      ] = await Promise.all([
        Article.find({
          article_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Video.find({
          video_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Interview.find({
          interview_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        PromptSet.find({
          promptset_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Exercise.find({
          exercise_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Template.find({
          template_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Nugget.find({
          title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean(),

        Mission.find({
          mission_title: regex,
          ...visibilityFilter
        })
          .limit(20)
          .lean()
      ]);

      /*
       * Apply organization topic restrictions.
       *
       * This is deliberately fail-open:
       * - unmapped topics remain searchable
       * - units with no recognized topic remain searchable
       * - multi-topic units remain searchable if at least one
       *   recognized topic is enabled
       */
      const visibleArticles =
        filterUnitsByTopic(
          articles,
          topicVisibility
        );

      const visibleVideos =
        filterUnitsByTopic(
          videos,
          topicVisibility
        );

      const visibleInterviews =
        filterUnitsByTopic(
          interviews,
          topicVisibility
        );

      const visiblePromptSets =
        filterUnitsByTopic(
          promptsets,
          topicVisibility
        );

      const visibleExercises =
        filterUnitsByTopic(
          exercises,
          topicVisibility
        );

      const visibleTemplates =
        filterUnitsByTopic(
          templates,
          topicVisibility
        );

      const visibleNuggets =
        filterUnitsByTopic(
          nuggets,
          topicVisibility
        );

      const visibleMissions =
        filterUnitsByTopic(
          missions,
          topicVisibility
        );

      /*
       * Convert the visible units into the format expected
       * by the library search interface.
       */
      const results = [
        ...visibleArticles.map(unit => ({
          unit_type: 'article',
          unit_id: unit._id,
          label:
            `Article – ${unit.article_title}`,
          value:
            `article:${unit._id}`
        })),

        ...visibleVideos.map(unit => ({
          unit_type: 'video',
          unit_id: unit._id,
          label:
            `Video – ${unit.video_title}`,
          value:
            `video:${unit._id}`
        })),

        ...visibleInterviews.map(unit => ({
          unit_type: 'interview',
          unit_id: unit._id,
          label:
            `Interview – ${unit.interview_title}`,
          value:
            `interview:${unit._id}`
        })),

        ...visiblePromptSets.map(unit => ({
          unit_type: 'promptset',
          unit_id: unit._id,
          label:
            `Prompt Set – ${unit.promptset_title}`,
          value:
            `promptset:${unit._id}`
        })),

        ...visibleExercises.map(unit => ({
          unit_type: 'exercise',
          unit_id: unit._id,
          label:
            `Exercise – ${unit.exercise_title}`,
          value:
            `exercise:${unit._id}`
        })),

        ...visibleTemplates.map(unit => ({
          unit_type: 'template',
          unit_id: unit._id,
          label:
            `Template – ${unit.template_title}`,
          value:
            `template:${unit._id}`
        })),

        ...visibleNuggets.map(unit => ({
          unit_type: 'nugget',
          unit_id: unit._id,
          label:
            `Nugget – ${unit.title}`,
          value:
            `nugget:${unit._id}`
        })),

        ...visibleMissions.map(unit => ({
          unit_type: 'mission',
          unit_id: unit._id,
          label:
            `Mission – ${unit.mission_title}`,
          value:
            `mission:${unit._id}`
        }))
      ];

      /*
       * Keep the autocomplete response compact.
       */
      return res.json(
        results.slice(0, 25)
      );
    } catch (err) {
      console.error(
        'Error searching library units:',
        err
      );

      return res.status(500).json({
        error:
          'Error searching library units'
      });
    }
  }
);

module.exports = router;