// controllers/unitSuggestionController.js
// Admin suggests a unit to one or more organization leaders

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');

// ✅ your model location
const UnitSuggestion = require('../models/unit_models/unit_suggestion');

// ✅ unit models for title/topic snapshots
const Article   = require('../models/unit_models/article');
const Video     = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const Interview = require('../models/unit_models/interview');
const Exercise  = require('../models/unit_models/exercise');
const Template  = require('../models/unit_models/template');
const Mission   = require('../models/unit_models/mission');
const Nugget    = require('../models/unit_models/nugget');

function toObjectId(id) {
  if (!id) return null;
  if (id instanceof mongoose.Types.ObjectId) return id;
  const s = String(id);
  return mongoose.Types.ObjectId.isValid(s) ? new mongoose.Types.ObjectId(s) : null;
}

// Always prefer fresh orgId (avoid stale req.user.organization)
async function getOrgIdForAdmin(req) {
  const adminId = req.user?._id;
  if (!adminId) return null;

  const admin = await Leader.findById(adminId)
    .select('organization organizationOptOut isAdmin')
    .lean();

  if (!admin?.isAdmin) return null;
  if (!admin?.organization || admin.organizationOptOut === true) return null;

  return toObjectId(admin.organization);
}

/**
 * Returns a lightweight snapshot for dashboards.
 * Update the select / field mapping here if any unit models use different field names.
 */
async function getUnitSnapshot(unitType, unitId) {
  const t = String(unitType || '').trim().toLowerCase();

  // Default shape
  const empty = { unitTitle: '', main_topic: '', secondary_topic: '' };

  if (!unitId) return empty;

  // Helper to normalize common variants
  const norm = (v) => (v == null ? '' : String(v).trim());

  switch (t) {
    case 'article': {
      const d = await Article.findById(unitId).select('article_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.article_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'video': {
      // Adjust if your video title field differs (e.g., video_title)
      const d = await Video.findById(unitId).select('video_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.video_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'promptset':
    case 'prompt_set':
    case 'prompt-set': {
      // Adjust if your prompt set title field differs (e.g., promptset_title)
      const d = await PromptSet.findById(unitId).select('promptset_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.promptset_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'interview': {
      // Adjust if your interview title field differs (e.g., interview_title)
      const d = await Interview.findById(unitId).select('interview_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.interview_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'exercise': {
      // Adjust if your exercise title field differs (e.g., exercise_title)
      const d = await Exercise.findById(unitId).select('exercise_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.exercise_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'template': {
      // Adjust if your template title field differs (e.g., template_title)
      const d = await Template.findById(unitId).select('template_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.template_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'mission': {
      // Adjust if your mission title field differs (e.g., mission_title)
      const d = await Mission.findById(unitId).select('mission_title main_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.mission_title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.sub_topic)
      };
    }

    case 'nugget': {
      // Nuggets may use different fields; adjust if needed.
      // Common patterns: nugget_title, title, main_topic, secondary_topic
      const d = await Nugget.findById(unitId).select('nugget_title title main_topic secondary_topic sub_topic').lean();
      return {
        unitTitle: norm(d?.nugget_title || d?.title),
        main_topic: norm(d?.main_topic),
        secondary_topic: norm(d?.secondary_topic || d?.sub_topic)
      };
    }

    default:
      return empty;
  }
}

const unitSuggestionController = {
  // POST /org-suggestions/create (or whatever route you mount)
  async create(req, res) {
    try {
      const orgId = await getOrgIdForAdmin(req);
      if (!orgId) return res.redirect('back');

      const suggestedBy = req.user?._id;
      const unitId = toObjectId(req.body.unitId);
      const unitType = String(req.body.unitType || '').trim().toLowerCase();

      if (!suggestedBy || !unitId || !unitType) return res.redirect('back');

      // suggestTo[<leaderId>][leader]=<leaderId>
      // suggestTo[<leaderId>][note]=...
      const suggestTo = req.body.suggestTo || {};

      const requestedLeaderIds = Object.keys(suggestTo)
        .filter(id => mongoose.Types.ObjectId.isValid(id))
        .map(id => new mongoose.Types.ObjectId(id));

      if (!requestedLeaderIds.length) return res.redirect('back');

      // Ensure recipients are leaders in the same org
      const validLeaders = await Leader.find({
        _id: { $in: requestedLeaderIds },
        organization: orgId,
        organizationOptOut: { $ne: true }
      })
.select('_id groupLeaderName username groupName')
        .lean();

      const validSet = new Set(validLeaders.map(l => String(l._id)));
      if (!validSet.size) return res.redirect('back');

      const snap = await getUnitSnapshot(unitType, unitId);

      const docs = requestedLeaderIds
        .filter(id => validSet.has(String(id)))
        .map(id => ({
          organization: orgId,
          suggestedBy,
          leaderId: id,

          unitId,
          unitType,

          // snapshot fields (make sure your schema supports these)
          unitTitle: snap.unitTitle,
          main_topic: snap.main_topic,
          secondary_topic: snap.secondary_topic,

          note: String(suggestTo[String(id)]?.note || '').trim(),
          status: 'pending'
        }));

      if (!docs.length) return res.redirect('back');

await UnitSuggestion.insertMany(docs, { ordered: false });

const suggestedNames = validLeaders
  .filter(l => validSet.has(String(l._id)))
  .map(l =>
    l.groupLeaderName ||
    l.username ||
    l.groupName ||
    'Leader'
  );

const ref = req.get('referer') || '';

return res.render('unit_views/suggest_success', {
  layout: 'unitviewlayout',
  unitLabel: unitType,
  unitTitle: snap.unitTitle || 'Untitled unit',
  suggestedNames,
  skippedDupesNames: [],
  dashboardUrl: '/dashboard/leader/org-admin/suggestions',
  unitUrl: ref
});

    } catch (err) {
      console.error('unitSuggestionController.create error:', err);
      return res.redirect('back');
    }
  }
};

module.exports = unitSuggestionController;
