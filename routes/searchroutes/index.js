// routes/searchroutes/index.js
const express = require('express');
const router = express.Router();

const Article   = require('../../models/unit_models/article');
const Video     = require('../../models/unit_models/video');
const Interview = require('../../models/unit_models/interview');
const PromptSet = require('../../models/unit_models/promptset');
const Exercise  = require('../../models/unit_models/exercise');
const Template  = require('../../models/unit_models/template');
const Nugget    = require('../../models/unit_models/nugget');
const Mission   = require('../../models/unit_models/mission');

const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// Helper: build a visibility filter based on the logged-in user.
// 🔴 TODO: adjust this to match your real visibility rules.
function buildVisibilityFilter(user) {
  const orConditions = [{ visibility: 'all_members' }];

  if (user && user.organization) {
    orConditions.push({
      visibility: 'organization_only',
      organization: user.organization
    });
  }

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
      // ✅ use article_title
      Article.find({ article_title: regex,    ...visibilityFilter }).limit(10).lean(),
      // ✅ use video_title
      Video.find({ video_title: regex,        ...visibilityFilter }).limit(10).lean(),
      // ✅ use interview_title
      Interview.find({ interview_title: regex, ...visibilityFilter }).limit(10).lean(),
      // ✅ still promptset_title
      PromptSet.find({ promptset_title: regex, ...visibilityFilter }).limit(10).lean(),
      // ✅ use exercise_title
      Exercise.find({ exercise_title: regex,  ...visibilityFilter }).limit(10).lean(),
      // ✅ use template_title
      Template.find({ template_title: regex,  ...visibilityFilter }).limit(10).lean(),
      // ✅ nuggets use plain title
      Nugget.find({ title: regex,             ...visibilityFilter }).limit(10).lean(),
      // ✅ missions use mission_title
      Mission.find({ mission_title: regex,    ...visibilityFilter }).limit(10).lean()
    ]);

    const results = [
      ...articles.map(u => ({
        unit_type: 'article',
        unit_id: u._id,
        label: `Article – ${u.article_title}`,
        value: `article:${u._id}`
      })),
      ...videos.map(u => ({
        unit_type: 'video',
        unit_id: u._id,
        label: `Video – ${u.video_title}`,
        value: `video:${u._id}`
      })),
      ...interviews.map(u => ({
        unit_type: 'interview',
        unit_id: u._id,
        label: `Interview – ${u.interview_title}`,
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
        label: `Exercise – ${u.exercise_title}`,
        value: `exercise:${u._id}`
      })),
      ...templates.map(u => ({
        unit_type: 'template',
        unit_id: u._id,
        label: `Template – ${u.template_title}`,
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

