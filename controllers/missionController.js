// controllers/missionController.js

const Mission = require('../models/unit_models/mission'); // adjust path if needed
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

function isPaidMember(req) {
  const t = req.user?.accessLevel || req.user?.membershipType;
  return ['paid_individual', 'leader', 'group_member'].includes(t);
}

// For now, keep it simple: one section per category
function makeSectionedMissions(missions, sectionTitle, emptyMessage) {
  return [
    {
      sectionTitle,
      missions,
      emptyMessage,
    },
  ];
}

// Generic helper for category pages
async function renderMissionList(req, res, options) {
  const {
    category,    // schema category: 'learning', 'research', 'business_development', etc.
    viewName,    // e.g. 'unit_views/missions_learning'
    pageTitle,   // {{title}} in the view
    shortSummary,
    longSummary,
  } = options;

  try {
    if (!isPaidMember(req)) {
      return res.status(403).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Access Restricted',
        errorMessage: 'Missions are available to paid members only.',
      });
    }

    const missions = await Mission.find({ category })
      .sort({ created_at: -1 }) // from schema
      .lean();

    const sectionedMissions = makeSectionedMissions(
      missions,
      'All missions',
      'No missions have been created in this category yet.'
    );

    return res.render(viewName, {
      layout: 'unitviewlayout',
      title: pageTitle,
      shortSummary,
      longSummary,
      sectionedMissions,
      loggedIn: !!req.user,
    });
  } catch (err) {
    console.error(`[${category} missions] error:`, err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading missions.',
    });
  }
}

module.exports = {
  // ------------------------------------
  // Mission Control (header square)
  // ------------------------------------
  missionControl: async (req, res) => {
    try {
      if (!isPaidMember(req)) {
        return res.status(403).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Access Restricted',
          errorMessage: 'Mission Control is available to paid members only.',
        });
      }

      return res.render('unit_views/missioncontrol_category', {
        layout: 'unitviewlayout',
        title: 'Mission Control',
        shortSummary: 'See and manage missions across all categories.',
        longSummary:
          'Mission Control is where you’ll eventually track missions by status, category, and assignee. ' +
          'For now, use it as a hub to jump into each mission category.',
        loggedIn: !!req.user,
      });
    } catch (err) {
      console.error('missionControl error:', err.stack || err.message);
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading Mission Control.',
      });
    }
  },

  // ------------------------------------
  // Category lists (matching your view names in /views/unit_views)
  // ------------------------------------

  // learning → /views/unit_views/missions_learning.hbs
  learningMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'learning',
      viewName: 'unit_views/missions_learning',
      pageTitle: 'Learning Missions',
      shortSummary: 'Missions that turn slow periods into focused learning sprints.',
      longSummary:
        'Use learning missions when you want people to build skills, explore a new topic, or work ' +
        'through Twennie units with a specific purpose while the workload is light.',
    }),

  // research → /views/unit_views/missions_research.hbs
  researchMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'research',
      viewName: 'unit_views/missions_research',
      pageTitle: 'Research Missions',
      shortSummary: 'Missions focused on market, client, and opportunity research.',
      longSummary:
        'Use research missions when you need to gather intel, understand a client, or explore a market ' +
        'before committing resources. These missions often feed directly into Nuggets and strategy work.',
    }),

  // business_development → /views/unit_views/missions_businessdevelopment.hbs
  businessDevelopmentMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'business_development',
      viewName: 'unit_views/missions_businessdevelopment',
      pageTitle: 'Business Development Missions',
      shortSummary: 'Missions that generate and advance opportunities.',
      longSummary:
        'Use business development missions to drive proactive outreach, strengthen relationships, and move ' +
        'opportunities from early curiosity toward real pursuits.',
    }),

  // internal_improvement → /views/unit_views/missions_internal_improvements.hbs
  internalImprovementMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'internal_improvement',
      viewName: 'unit_views/missions_internal_improvements',
      pageTitle: 'Internal Improvement Missions',
      shortSummary: 'Missions that improve internal systems, tools, and workflows.',
      longSummary:
        'Use internal improvement missions to tighten processes, remove friction, and make daily work ' +
        'easier and more effective for your team.',
    }),

  // client_experience → /views/unit_views/missions_clientexperience.hbs
  clientExperienceMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'client_experience',
      viewName: 'unit_views/missions_clientexperience',
      pageTitle: 'Client Experience Missions',
      shortSummary: 'Missions that elevate the client’s day-to-day experience.',
      longSummary:
        'Use client experience missions to design better touchpoints, communication, and follow-up. ' +
        'These missions help un-commoditize your services and make clients feel genuinely looked after.',
    }),

  // culture_play → /views/unit_views/missions_cultureandplay.hbs
  cultureAndPlayMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'culture_play',
      viewName: 'unit_views/missions_cultureandplay',
      pageTitle: 'Culture & Play Missions',
      shortSummary: 'Missions that build culture, play, and human connection.',
      longSummary:
        'Use culture and play missions to experiment with fun, rituals, and connection that make work ' +
        'feel more human — and projects easier to deliver.',
    }),

  // administrative → /views/unit_views/missions_administrative.hbs
  administrativeMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'administrative',
      viewName: 'unit_views/missions_administrative',
      pageTitle: 'Administrative Missions',
      shortSummary: 'Missions that handle the necessary operational and admin work.',
      longSummary:
        'Use administrative missions to tackle the important-but-not-urgent tasks that keep your firm ' +
        'organized, compliant, and prepared when things get busy again.',
    }),

  // other → /views/unit_views/missions_rogue.hbs
  rogueMissions: (req, res) =>
    renderMissionList(req, res, {
      category: 'other',
      viewName: 'unit_views/missions_rogue',
      pageTitle: 'Rogue Missions',
      shortSummary: 'Wild-card missions that don’t fit any one category.',
      longSummary:
        'Use rogue missions for experiments, oddball ideas, and cross-cutting initiatives. These are ' +
        'the “this doesn’t fit anywhere, but it matters” missions.',
    }),

  // ------------------------------------
  // Single mission view (draft)
  // ------------------------------------
  viewMission: async (req, res) => {
    try {
      const { id } = req.params;

      if (!isPaidMember(req)) {
        return res.status(403).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Access Restricted',
          errorMessage: 'Missions are available to paid members only.',
        });
      }

      const mission = await Mission.findById(id).lean();
      if (!mission) {
        return res.status(404).render('unit_views/error', {
          layout: 'unitviewlayout',
          title: 'Mission Not Found',
          errorMessage: 'The requested mission could not be found.',
        });
      }

      // 🚧 Draft: for now, just pass the full mission object.
      // Later we’ll:
      //  - resolve created_by and assigned_to to profiles
      //  - add visibility / access checks if needed
      //  - expose completions in a nicer structure
      return res.render('unit_views/single_mission', {
        layout: 'unitviewlayout',
        title: mission.mission_title,
        mission,          // all schema fields available as mission.*
        loggedIn: !!req.user,
      });
    } catch (err) {
      console.error('viewMission error:', err.stack || err.message);
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading this mission.',
      });
    }
  },
};
