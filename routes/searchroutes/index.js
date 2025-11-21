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

const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// Helper: build a visibility filter based on the logged-in user.
// 🚨 IMPORTANT: adjust this to match your real visibility logic.
function buildVisibilityFilter(user) {
  // Start with global units everyone can see
  const orConditions = [{ visibility: 'all_members' }];

  // Example: organization-only units
  if (user && user.organization) {
    orConditions.push({
      visibility: 'organization_only',
      organization: user.organization
    });
  }

  // Example: team-only units (adjust field names to your schema)
  if (user && Array.isArray(user.teams) && user.teams.length > 0) {
    orConditions.push({
      visibility: 'team_only',
      team: { $in: user.teams }
    });
  }

  return { $or: orConditions };
}

// GET /search/library-units?q=keyword
router.get('/library-units', ensureAuthenticated, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();

    if (q.length < 2) {
      return res.json([]);
    }

    const regex = new RegExp(q, 'i'); // case-insensitive
    const visibilityFilter = buildVisibilityFilter(req.user);

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
      Article.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      Video.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      Interview.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      PromptSet.find({ promptset_title: regex, ...visibilityFilter }).limit(10).lean(),
      Exercise.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      Template.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      Nugget.find({ title: regex, ...visibilityFilter }).limit(10).lean(),
      Mission.find({ mission_title: regex, ...visibilityFilter }).limit(10).lean()
    ]);

    const results = [
      ...articles.map(u => ({
        unit_type: 'article',
        unit_id: u._id,
        label: `Article – ${u.title}`,
        value: `article:${u._id}`
      })),
      ...videos.map(u => ({
        unit_type: 'video',
        unit_id: u._id,
        label: `Video – ${u.title}`,
        value: `video:${u._id}`
      })),
      ...interviews.map(u => ({
        unit_type: 'interview',
        unit_id: u._id,
        label: `Interview – ${u.title}`,
        value: `interview:${u._id}`
      })),
      ...promptsets.map(u => ({
        unit_type: 'promptset',
        unit_id: u._id,
        label: `Prompt Set – ${u.promptset_title}`,
        value: `promptset:${u._id}`
      })),
      ...exercises.map(u => ({
        unit_type: 'exercise',
        unit_id: u._id,
        label: `Exercise – ${u.title}`,
        value: `exercise:${u._id}`
      })),
      ...templates.map(u => ({
        unit_type: 'template',
        unit_id: u._id,
        label: `Template – ${u.title}`,
        value: `template:${u._id}`
      })),
      ...nuggets.map(u => ({
        unit_type: 'nugget',
        unit_id: u._id,
        label: `Nugget – ${u.title}`,
        value: `nugget:${u._id}`
      })),
      ...missions.map(u => ({
        unit_type: 'mission',
        unit_id: u._id,
        label: `Mission – ${u.mission_title}`,
        value: `mission:${u._id}`
      }))
    ];

    // Keep the response small and snappy
    res.json(results.slice(0, 25));
  } catch (err) {
    console.error('Error searching library units:', err);
    res.status(500).json({ error: 'Error searching library units' });
  }
});

module.exports = router;
