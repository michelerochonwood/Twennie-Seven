// controllers/orgadminController.js
// Org Admin Controller (Admin Mode only)
// Renders the SAME leader_dashboard view, with adminMode=true.
// IMPORTANT: We preload ALL admin-mode data on every admin route render
// so admin tabs can switch client-side with no flash / missing data.

const mongoose = require('mongoose');

const Leader = require('../models/member_models/leader');
const Organization = require('../models/member_models/organization');
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');
const GroupProfile = require('../models/profile_models/group_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const Notes = require('../models/notes/notes');
const UnitSuggestion = require('../models/unit_models/unit_suggestion'); // optional if you pick suggestions metric
const Article   = require('../models/unit_models/article');
const Video     = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const Interview = require('../models/unit_models/interview');
const Exercise  = require('../models/unit_models/exercise');
const Template  = require('../models/unit_models/template');
const Mission   = require('../models/unit_models/mission');
const Nugget    = require('../models/unit_models/nugget');
const GroupMember = require('../models/member_models/group_member');
const Upcoming = require('../models/unit_models/upcoming');
const OrganizationProfile = require('../models/profile_models/organization_profile');
const DashboardSeen = require('../models/dashboard_seen');
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const Tag = require('../models/tag');


// -----------------------------
// Helpers
// -----------------------------


const resolveUnitDetails = async (unitID) => {
  if (!unitID) {
    return {
      unitTitle: "Unknown Unit",
      unitType: "Unknown",
      main_topic: "Unknown",
      secondary_topics: []
    };
  }

  const id = unitID.toString();

  // Helper to normalize common fields
  const normalize = (doc, title, type) => ({
    unitTitle: title || "Unknown Unit",
    unitType: type || "Unknown",
    main_topic: doc?.main_topic || "Unknown Topic",
    secondary_topics: Array.isArray(doc?.secondary_topics) ? doc.secondary_topics : []
  });

  // Try each model in priority order
  const article = await Article.findById(id).select("article_title main_topic secondary_topics").lean();
  if (article) return normalize(article, article.article_title, "Article");

  const video = await Video.findById(id).select("video_title main_topic secondary_topics").lean();
  if (video) return normalize(video, video.video_title, "Video");

  const interview = await Interview.findById(id).select("interview_title main_topic secondary_topics").lean();
  if (interview) return normalize(interview, interview.interview_title, "Interview");

  const exercise = await Exercise.findById(id).select("exercise_title main_topic secondary_topics").lean();
  if (exercise) return normalize(exercise, exercise.exercise_title, "Exercise");

  const template = await Template.findById(id).select("template_title main_topic secondary_topics").lean();
  if (template) return normalize(template, template.template_title, "Template");

  const promptSet = await PromptSet.findById(id).select("promptset_title main_topic secondary_topics").lean();
  if (promptSet) return normalize(promptSet, promptSet.promptset_title, "Prompt Set");

  // ✅ Missions
  // Your mission topics live on main_topic/secondary_topics; title is mission_title
  const mission = await Mission.findById(id).select("mission_title main_topic secondary_topics").lean();
  if (mission) return normalize(mission, mission.mission_title, "Mission");

  // ✅ Nuggets
  // Nuggets don’t necessarily have topics; treat discipline/client/region as the “main_topic”
  const nugget = await Nugget.findById(id).select("title discipline client region").lean();
  if (nugget) {
    return {
      unitTitle: nugget.title || "Untitled Nugget",
      unitType: "Nugget",
      main_topic: nugget.discipline || nugget.client || nugget.region || "Unknown Topic",
      secondary_topics: []
    };
  }

  // ✅ Upcoming Units
  // Upcoming uses title + main_topic; no secondary_topics typically
  const upcoming = await Upcoming.findById(id).select("title unit_type main_topic secondary_topics").lean();
  if (upcoming) {
    const planned = upcoming.unit_type ? ` (${upcoming.unit_type})` : "";
    return {
      unitTitle: (upcoming.title || "Upcoming Unit") + planned,
      unitType: "Upcoming",
      main_topic: upcoming.main_topic || "Unknown Topic",
      secondary_topics: Array.isArray(upcoming.secondary_topics) ? upcoming.secondary_topics : []
    };
  }

  return {
    unitTitle: "Unknown Unit",
    unitType: "Unknown",
    main_topic: "Unknown",
    secondary_topics: []
  };
};



async function baseRenderData(req) {
  const leader = await Leader.findById(req.user?._id || req.user?.id)
    .select([
      '_id',
      'groupLeaderName',
      'groupName',
      'profileImage',
      'organization',
      'organizationName',
      'isAdmin'
    ].join(' '))
    .lean();

  let organizationLogo = null;

  if (leader?.organization) {
    const orgProfile = await OrganizationProfile.findOne({
      organizationId: leader.organization
    })
      .select('logo')
      .lean();

    organizationLogo = orgProfile?.logo?.url || null;
  }

  return {
    layout: 'dashboardlayout',
    title: 'Leader Dashboard',
    adminMode: true,
    leader,
    organizationLogo,
    csrfToken: req.csrfToken ? req.csrfToken() : null
  };
}

function safeNumber(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v : 0;
}

function toObjectId(id) {
  if (!id) return null;
  if (id instanceof mongoose.Types.ObjectId) return id;
  const s = String(id);
  return mongoose.Types.ObjectId.isValid(s) ? new mongoose.Types.ObjectId(s) : null;
}

// Always prefer a fresh orgId from DB (avoid stale req.user.organization)
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


function fmtDate(d) {
  if (!d) return '';
  const dd = new Date(d);
  if (Number.isNaN(dd.getTime())) return '';
  return dd.toLocaleDateString('en-CA', { year: 'numeric', month: 'short', day: '2-digit' });
}

function viewPathForUnit(unitType, unitId) {
  const t = String(unitType || '').toLowerCase();
  const id = unitId?.toString?.() || String(unitId || '');

  if (t === 'nugget')  return `/unitviews/nuggets/view/${id}`;
  if (t === 'mission') return `/unitviews/missions/view/${id}`;
  return `/unitviews/${t}s/view/${id}`;
}

function pickTitle(unit) {
  return (
    unit.mission_title ||
    unit.article_title ||
    unit.video_title ||
    unit.promptset_title ||
    unit.interview_title ||
    unit.exercise_title ||
    unit.template_title ||
    unit.title ||
    unit.name ||
    'Untitled Unit'
  );
}

function pickMainTopic(unit) {
  return unit.main_topic || unit.discipline || unit.client || unit.region || 'No topic';
}

function normalizeUnitTypeFromDoc(doc) {
  if (doc.article_title) return 'article';
  if (doc.video_title) return 'video';
  if (doc.promptset_title) return 'promptset';
  if (doc.interview_title) return 'interview';
  if (doc.exercise_title) return 'exercise';
  if (doc.template_title) return 'template';
  if (doc.mission_title) return 'mission';
  if (doc.title && (doc.discipline || doc.client || doc.region)) return 'nugget';
  return 'unknown';
}


async function buildLibrarySubmissionsCount(orgId) {
  // NOTE: this is now ALL-TIME (no date filter)

  // org people = leaders + their members
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };
  const leaders = await Leader.find(leaderFilter).select('_id members').lean();
  if (!leaders.length) return 0;

  const idSet = new Set();
  for (const l of leaders) {
    if (l?._id) idSet.add(String(l._id));
    if (Array.isArray(l.members)) {
      for (const m of l.members) idSet.add(String(m));
    }
  }

  const orgPersonIds = Array.from(idSet)
    .filter(s => mongoose.Types.ObjectId.isValid(s))
    .map(s => new mongoose.Types.ObjectId(s));

  if (!orgPersonIds.length) return 0;

  const [
    articlesCreated,
    videosCreated,
    promptSetsCreated,
    interviewsCreated,
    exercisesCreated,
    templatesCreated,
    missionsCreated,
    nuggetsCreated
  ] = await Promise.all([
    Article.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Video.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    PromptSet.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Interview.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Exercise.countDocuments({ 'author.id': { $in: orgPersonIds } }),
    Template.countDocuments({ 'author.id': { $in: orgPersonIds } }),

    // missions/nuggets use different creator fields in your app
    Mission.countDocuments({ created_by: { $in: orgPersonIds } }),
    Nugget.countDocuments({ createdBy: { $in: orgPersonIds } })
  ]);

  return (
    articlesCreated +
    videosCreated +
    promptSetsCreated +
    interviewsCreated +
    exercisesCreated +
    templatesCreated +
    missionsCreated +
    nuggetsCreated
  );
}


// -----------------------------
// Snapshot builders
// -----------------------------
async function buildOrgSnapshot(orgId) {
  const organization = await Organization.findById(orgId).lean();

  const empty = {
    organization: null,
    counts: {
      leaders: 0,
      groups: 0,
      members: 0,
      pendingJoinRequests: 0,
      pendingLibrarySubmissions: 0,
      suggestionsSent: 0
    },
    pendingJoinRequestsList: [],
    learningFootprint: {
      activeLearners: 0,
      unitsCompleted: 0,
      promptSetsCompleted: 0,
      avgCompletionsPerLearner: 0,
      mostPopularTopic: '—'
    }
  };

  if (!organization) return empty;

  const leaderFilter = {
    organization: orgId,
    organizationOptOut: { $ne: true }
  };

  const [
    leadersCount,
    distinctGroupNames,
    membersAgg,
    pendingJoinRequestsList,
    learningFootprint,
    suggestionsSent,
    pendingLibrarySubmissions
  ] = await Promise.all([
    // leaders
    Leader.countDocuments(leaderFilter),

    // groups (distinct group names)
    Leader.distinct('groupName', leaderFilter),

    // members (sum of leader.members[])
    Leader.aggregate([
      { $match: leaderFilter },
      {
        $project: {
          memberCount: { $size: { $ifNull: ['$members', []] } }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$memberCount' }
        }
      }
    ]),

    // join requests
    OrganizationJoinRequest.find({
      organization: orgId,
      status: 'pending'
    })
      .populate(
        'leader',
        'groupLeaderName groupLeaderEmail username groupName profileImage'
      )
      .sort({ requestedAt: -1 })
      .lean(),

    // learning footprint (30 days is fine here)
    buildLearningFootprintForOrg(orgId, 30),

    // ✅ ALL-TIME suggestions
UnitSuggestion.countDocuments({
  $or: [{ organization: orgId }, { organization: String(orgId) }]
}),

    // ✅ ALL-TIME library submissions
    buildLibrarySubmissionsCount(orgId)
  ]);

  const groupsCount = (distinctGroupNames || [])
    .map(n => String(n || '').trim())
    .filter(Boolean).length;

  const membersCount = membersAgg?.[0]?.total || 0;

  return {
    organization,
    counts: {
      leaders: safeNumber(leadersCount),
      groups: safeNumber(groupsCount),
      members: safeNumber(membersCount),
      pendingJoinRequests: safeNumber(pendingJoinRequestsList.length),
      pendingLibrarySubmissions: safeNumber(pendingLibrarySubmissions),
      suggestionsSent: safeNumber(suggestionsSent)
    },
    pendingJoinRequestsList,
    learningFootprint: learningFootprint || empty.learningFootprint
  };
}


async function buildOrgLeaderLibraries(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  // all leaders (groups) in org
  const leaders = await Leader.find(leaderFilter)
    .select('_id groupName groupLeaderName members groupSize')
    .sort({ groupName: 1 })
    .lean();

  if (!leaders.length) return [];

  const rows = [];

  for (const leader of leaders) {
    const leaderId = leader._id;
    const leaderIdStr = leaderId.toString();

    // group members for this leader
    const groupMembers = await GroupMember.find({ groupId: leaderId })
      .select('_id name')
      .lean();

    const groupMemberIds = groupMembers.map(m => m._id);
    const memberNameById = new Map(groupMembers.map(m => [m._id.toString(), m.name]));

    // ----- leader units (authored by leader) -----
    const [
      leaderArticles,
      leaderVideos,
      leaderPromptSets,
      leaderInterviews,
      leaderExercises,
      leaderTemplates,
      leaderUpcomings,
      leaderNuggets,
      leaderMissions
    ] = await Promise.all([
      Article.find({ 'author.id': leaderIdStr }).lean(),
      Video.find({ 'author.id': leaderIdStr }).lean(),
      PromptSet.find({ 'author.id': leaderIdStr }).lean(),
      Interview.find({ 'author.id': leaderIdStr }).lean(),
      Exercise.find({ 'author.id': leaderIdStr }).lean(),
      Template.find({ 'author.id': leaderIdStr }).lean(),
      Upcoming.find({ createdBy: leaderId }).lean(),
      Nugget.find({ createdBy: leaderId }).lean(),
      Mission.find({ $or: [{ created_by: leaderId }, { createdBy: leaderId }] }).lean()
    ]);

    const leaderUnits = [
      ...leaderArticles,
      ...leaderVideos,
      ...leaderPromptSets,
      ...leaderInterviews,
      ...leaderExercises,
      ...leaderTemplates,
      ...(leaderUpcomings || []),
      ...(leaderNuggets || []),
      ...(leaderMissions || [])
    ].map(u => {
      const unitType = u.unit_type ? 'upcoming' : normalizeUnitTypeFromDoc(u);
      return {
        unitType,
        plannedType: u.unit_type || null, // upcoming only
        title: pickTitle(u),
        status: u.status || (unitType === 'nugget' ? '—' : 'Unknown'),
        mainTopic: pickMainTopic(u),
        _id: u._id,
        projectedRelease: u.projected_release_at || u.projectedRelease || null
      };
    });

    // ----- group member units (authored by group members) -----
    const [
      gmArticles,
      gmVideos,
      gmPromptSets,
      gmInterviews,
      gmExercises,
      gmTemplates,
      gmUpcomings,
      gmNuggets,
      gmMissions
    ] = await Promise.all([
      Article.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Video.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      PromptSet.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Interview.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Exercise.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Template.find({ 'author.id': { $in: groupMemberIds } }).lean(),
      Upcoming.find({ createdBy: { $in: groupMemberIds } }).lean(),
      Nugget.find({ createdBy: { $in: groupMemberIds } }).lean(),
      Mission.find({ $or: [{ created_by: { $in: groupMemberIds } }, { createdBy: { $in: groupMemberIds } }] }).lean()
    ]);

    const groupMemberUnits = [
      ...gmArticles,
      ...gmVideos,
      ...gmPromptSets,
      ...gmInterviews,
      ...gmExercises,
      ...gmTemplates,
      ...(gmUpcomings || []),
      ...(gmNuggets || []),
      ...(gmMissions || [])
    ].map(u => {
      const unitType = u.unit_type ? 'upcoming' : normalizeUnitTypeFromDoc(u);
      const authorId = (u.createdBy || u.author?.id || u.author || u.created_by || '').toString?.() || '';

      return {
        author: memberNameById.get(authorId) || 'Group Member',
        unitType,
        plannedType: u.unit_type || null, // upcoming only
        title: pickTitle(u),
        status: u.status || (unitType === 'nugget' ? '—' : 'Unknown'),
        mainTopic: pickMainTopic(u),
        _id: u._id,
        projectedRelease: u.projected_release_at || u.projectedRelease || null
      };
    });

    rows.push({
      leaderId: leaderIdStr,
      leaderName: leader.groupLeaderName || leader.username || 'Leader',
      groupName: leader.groupName || 'Unnamed group',
      leaderUnits,
      groupMemberUnits
    });
  }

  return rows;
}


function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

/**
 * Learning footprint (last N days) for an organization.
 * Assumes:
 * - Non-prompt units are "completed" when a Notes doc is created.
 * - Prompt sets are "completed" when a PromptSetCompletion doc indicates completion.
 *
 * IMPORTANT: This computes footprint for users currently in org (leaders + their members).
 * If you truly want "from this point forward" only, this is already essentially that,
 * because it only looks back 30 days.
 */
async function buildLearningFootprintForOrg(orgId, days = 30) {
  const since = daysAgo(days);

  const empty = {
    activeLearners: 0,
    unitsCompleted: 0,
    promptSetsCompleted: 0,
    avgCompletionsPerLearner: 0,
    mostPopularTopic: '—'
  };

  // leaders in org
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };
  const leaders = await Leader.find(leaderFilter).select('_id members').lean();

  if (!leaders.length) return empty;

  // Build learner ids: leaders + their members
  const learnerIdSet = new Set();
  for (const l of leaders) {
    if (l?._id) learnerIdSet.add(String(l._id));
    if (Array.isArray(l.members)) {
      for (const m of l.members) learnerIdSet.add(String(m));
    }
  }

  const learnerIds = Array.from(learnerIdSet)
    .filter(s => mongoose.Types.ObjectId.isValid(s))
    .map(s => new mongoose.Types.ObjectId(s));

  if (!learnerIds.length) return empty;

  // Notes completions (non-prompt units) + most popular topic from Notes.main_topic
  const notesAgg = await Notes.aggregate([
    {
      $match: {
        createdAt: { $gte: since },
        memberID: { $in: learnerIds }
      }
    },
    {
      $project: {
        memberID: 1,
        main_topic: { $trim: { input: { $ifNull: ['$main_topic', ''] } } }
      }
    },
    {
      $facet: {
        // totals + active learners
        totals: [
          {
            $group: {
              _id: null,
              unitsCompleted: { $sum: 1 },
              activeLearnerSet: { $addToSet: '$memberID' }
            }
          }
        ],

        // most popular topic (ignore blanks)
        topTopic: [
          { $match: { main_topic: { $ne: '' } } },
          { $group: { _id: '$main_topic', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 1 }
        ]
      }
    }
  ]);

  const totals = notesAgg?.[0]?.totals?.[0] || null;
  const unitsCompleted = totals?.unitsCompleted || 0;

  const activeFromNotesArr = totals?.activeLearnerSet || [];
  const activeFromNotes = new Set(activeFromNotesArr.map(id => String(id)));

  const mostPopularTopic =
    notesAgg?.[0]?.topTopic?.[0]?._id ? String(notesAgg[0].topTopic[0]._id) : '—';

  // Prompt set completions
  const pscAgg = await PromptSetCompletion.aggregate([
    {
      $match: {
        completedAt: { $gte: since },
        memberId: { $in: learnerIds }
      }
    },
    {
      $group: {
        _id: null,
        promptSetsCompleted: { $sum: 1 },
        activeLearnerSet: { $addToSet: '$memberId' }
      }
    }
  ]);

  const promptSetsCompleted = pscAgg?.[0]?.promptSetsCompleted || 0;
  const activeFromPSCArr = pscAgg?.[0]?.activeLearnerSet || [];
  const activeFromPSC = new Set(activeFromPSCArr.map(id => String(id)));

  // Union active learners (notes OR prompt sets)
  const activeLearners = new Set([...activeFromNotes, ...activeFromPSC]).size;

  const avgCompletionsPerLearner =
    activeLearners > 0 ? Number((unitsCompleted / activeLearners).toFixed(2)) : 0;

  return {
    activeLearners: safeNumber(activeLearners),
    unitsCompleted: safeNumber(unitsCompleted),
    promptSetsCompleted: safeNumber(promptSetsCompleted),
    avgCompletionsPerLearner,
    mostPopularTopic
  };
}



async function buildOrgGroupsLeaders(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leaders = await Leader.find(leaderFilter)
    .select('_id groupLeaderName groupName profileImage members groupSize')
    .sort({ groupName: 1 })
    .lean();

  if (!leaders.length) return [];

  const ids = leaders.map(l => l._id);

  const [groupProfiles, leaderProfiles] = await Promise.all([
    // Group images
    GroupProfile.find({ groupId: { $in: ids } })
      .select('groupId groupImage')
      .lean(),

    // Leader profile images (true “leader avatar”)
    LeaderProfile.find({ leaderId: { $in: ids } })
      .select('leaderId profileImage')
      .lean()
  ]);

  const groupImgByLeaderId = new Map(groupProfiles.map(p => [p.groupId.toString(), p.groupImage]));
  const leaderImgByLeaderId = new Map(leaderProfiles.map(p => [p.leaderId.toString(), p.profileImage]));

  return leaders.map(l => {
    const idStr = l._id.toString();

    return {
      _id: l._id,
      groupName: l.groupName || 'Unnamed group',
      groupLeaderName: l.groupLeaderName || '—',
      leaderId: l._id,

      leaderImage:
        leaderImgByLeaderId.get(idStr) ||
        l.profileImage ||
        '/images/default-avatar.png',

      groupImage:
        groupImgByLeaderId.get(idStr) ||
        '/images/default-group.png',

      memberCount: Array.isArray(l.members) ? l.members.length : (l.groupSize || 0)
    };
  });
}

// ✅ Admin: Team Engagement across teams (org-wide)
// Updated to return:
// - groupImage (from GroupProfile)
// - promptSetsCompleted: ALL prompt set titles completed by the team (deduped, alphabetized)
// - unitsCompleted: ALL unit titles completed by the team (deduped, alphabetized; missions excluded)
// - topTopics (unchanged)
// Removed counts that your new partial no longer uses.
async function buildAdminTeamEngagement(orgId) {
  const leaderFilter = { organization: orgId, organizationOptOut: { $ne: true } };

  const leaders = await Leader.find(leaderFilter)
    .select('_id groupName groupLeaderName name members profileImage')
    .sort({ groupName: 1 })
    .lean();

  if (!leaders.length) return [];

  const leaderIds = leaders.map(l => l._id);

  const [groupProfiles, leaderProfiles] = await Promise.all([
    GroupProfile.find({ groupId: { $in: leaderIds } })
      .select('groupId groupImage')
      .lean(),

    LeaderProfile.find({ leaderId: { $in: leaderIds } })
      .select('leaderId profileImage')
      .lean()
  ]);

  const groupImgByLeaderId = new Map(
    (groupProfiles || []).map(p => [p.groupId.toString(), p.groupImage])
  );

  const leaderImgByLeaderId = new Map(
    (leaderProfiles || []).map(p => [p.leaderId.toString(), p.profileImage])
  );

  const allPersonIdSet = new Set();

  for (const leader of leaders) {
    if (leader?._id) allPersonIdSet.add(String(leader._id));

    if (Array.isArray(leader.members)) {
      for (const m of leader.members) {
        allPersonIdSet.add(String(m));
      }
    }
  }

  const allPersonIds = Array.from(allPersonIdSet)
    .filter(s => mongoose.Types.ObjectId.isValid(s))
    .map(s => new mongoose.Types.ObjectId(s));

  const [
    promptCompletions,
    notes,
    tags,
    promptAssignments,
    nuggets,
    missions
  ] = await Promise.all([
    PromptSetCompletion.find({ memberId: { $in: allPersonIds } })
      .populate('promptSetId', 'promptset_title main_topic secondary_topics badge_name badgeImage badgeImagePath')
      .lean(),

    Notes.find({ memberID: { $in: allPersonIds } }).lean(),

    Tag.find({ 'assignedTo.member': { $in: allPersonIds } }).lean(),

AssignPromptSet.find({
  assignedMemberIds: { $in: allPersonIds }
})
      .populate('promptSetId', 'promptset_title badge_name badgeImage badgeImagePath main_topic secondary_topics')
      .lean(),

    Nugget.find({
      'monitoringNotes.addedBy': { $in: allPersonIds }
    }).lean(),

    Mission.find({}).lean()
  ]);

  const completionsByPerson = new Map();
  for (const c of promptCompletions || []) {
    const pid = c.memberId?.toString?.() || '';
    if (!pid) continue;
    if (!completionsByPerson.has(pid)) completionsByPerson.set(pid, []);
    completionsByPerson.get(pid).push(c);
  }

  const notesByPerson = new Map();
  for (const n of notes || []) {
    const pid = n.memberID?.toString?.() || '';
    if (!pid) continue;
    if (!notesByPerson.has(pid)) notesByPerson.set(pid, []);
    notesByPerson.get(pid).push(n);
  }

  const unitCache = new Map();

  const reports = [];

  for (const leader of leaders) {
    const leaderIdStr = leader._id.toString();
    const memberIds = Array.isArray(leader.members)
      ? leader.members.map(x => x.toString())
      : [];

    const teamPersonIds = [leaderIdStr, ...memberIds];
    const teamPersonIdSet = new Set(teamPersonIds);

    const teamObjectIds = teamPersonIds
      .filter(s => mongoose.Types.ObjectId.isValid(s))
      .map(s => new mongoose.Types.ObjectId(s));

    const teamNotes = teamPersonIds.flatMap(pid => notesByPerson.get(pid) || []);
    const teamPromptComps = teamPersonIds.flatMap(pid => completionsByPerson.get(pid) || []);

    const completedUnitIdSet = new Set(
      teamNotes
        .map(n => n.unitID ? String(n.unitID) : '')
        .filter(Boolean)
    );

    const completedMissionIdSet = new Set(
      teamNotes
        .filter(n => String(n.unitType || '').toLowerCase() === 'mission')
        .map(n => n.unitID ? String(n.unitID) : '')
        .filter(Boolean)
    );

    const completedPromptSetTitleSet = new Set();
    const promptSetBadgesEarned = [];

    for (const completion of teamPromptComps) {
      const ps = completion.promptSetId || {};
      const title = ps.promptset_title || completion.promptSetTitle || 'Untitled prompt set';

      completedPromptSetTitleSet.add(title);

      const badgeName =
        completion.badgeName ||
        ps.badge_name ||
        title;

      const badgeImage =
        completion.badgeImage ||
        completion.badgeImagePath ||
        ps.badgeImage ||
        ps.badgeImagePath ||
        '';

      promptSetBadgesEarned.push({
        badgeName,
        badgeImage
      });
    }

    const promptSetsCompleted = Array.from(completedPromptSetTitleSet)
      .sort((a, b) => a.localeCompare(b));

    const promptSetBadgesUnique = [];
    const seenPromptBadges = new Set();

    for (const badge of promptSetBadgesEarned) {
      const key = `${badge.badgeName}:${badge.badgeImage}`;
      if (seenPromptBadges.has(key)) continue;
      seenPromptBadges.add(key);
      promptSetBadgesUnique.push(badge);
    }

    const topicsFromCompletions = teamPromptComps.flatMap(p => {
      const ps = p.promptSetId || {};
      const main = ps.main_topic ? [ps.main_topic] : [];
      const secs = Array.isArray(ps.secondary_topics) ? ps.secondary_topics : [];
      return [...main, ...secs];
    });

    const nonMissionNotes = teamNotes.filter(
      n => String(n.unitType || '').toLowerCase() !== 'mission'
    );

    const distinctCompletedUnitIds = Array.from(
      new Set(nonMissionNotes.map(n => n.unitID ? String(n.unitID) : '').filter(Boolean))
    );

    const unitTitleSet = new Set();
    const topicsFromCompletedUnits = [];

    for (const uid of distinctCompletedUnitIds) {
      let details = unitCache.get(uid);

      if (!details) {
        details = await resolveUnitDetails(uid);
        unitCache.set(uid, details);
      }

      if (String(details.unitType || '').toLowerCase() === 'mission') continue;

      if (details.unitTitle) unitTitleSet.add(details.unitTitle);

      if (details.main_topic) topicsFromCompletedUnits.push(details.main_topic);
      if (Array.isArray(details.secondary_topics)) {
        topicsFromCompletedUnits.push(...details.secondary_topics);
      }
    }

    const unitsCompleted = Array.from(unitTitleSet)
      .sort((a, b) => a.localeCompare(b));

    const incompleteUnits = [];

    for (const tag of tags || []) {
      const assignedTo = Array.isArray(tag.assignedTo) ? tag.assignedTo : [];

      const teamAssignments = assignedTo.filter(a => {
        const memberId = a?.member?.toString?.() || '';
        return teamPersonIdSet.has(memberId);
      });

      if (!teamAssignments.length) continue;

      const associatedUnits = Array.isArray(tag.associatedUnits) ? tag.associatedUnits : [];

      for (const au of associatedUnits) {
        const unitId = au.item?.toString?.() || au.unitId?.toString?.() || '';
        const unitType = String(au.unitType || au.itemType || '').toLowerCase();

        if (!unitId) continue;
        if (completedUnitIdSet.has(unitId)) continue;
        if (unitType === 'mission') continue;
        if (unitType === 'nugget') continue;

        let details = unitCache.get(unitId);

        if (!details) {
          details = await resolveUnitDetails(unitId);
          unitCache.set(unitId, details);
        }

        incompleteUnits.push({
          title: details.unitTitle || tag.tagName || 'Assigned unit',
          unitType: details.unitType || unitType || 'Unit',
          assignedAtFormatted: fmtDate(tag.createdAt || tag.updatedAt),
          viewPath: viewPathForUnit(unitType || details.unitType, unitId)
        });
      }
    }

    const incompleteUnitsUnique = [];
    const seenIncomplete = new Set();

    for (const item of incompleteUnits) {
      const key = `${item.title}:${item.assignedAtFormatted}`;
      if (seenIncomplete.has(key)) continue;
      seenIncomplete.add(key);
      incompleteUnitsUnique.push(item);
    }

    const completedPromptSetIds = new Set(
      teamPromptComps
        .map(c => c.promptSetId?._id?.toString?.() || c.promptSetId?.toString?.() || '')
        .filter(Boolean)
    );

    const promptSetsInProgress = [];

    for (const assignment of promptAssignments || []) {

      const assignedIds = Array.isArray(assignment.assignedMemberIds)
  ? assignment.assignedMemberIds.map(id => id.toString())
  : [];

const belongsToTeam = assignedIds.some(id => teamPersonIdSet.has(id));

      if (!belongsToTeam) continue;

      const psId =
        assignment.promptSetId?._id?.toString?.() ||
        assignment.promptSetId?.toString?.() ||
        '';

      if (psId && completedPromptSetIds.has(psId)) continue;

      const title =
        assignment.promptSetId?.promptset_title ||
        assignment.promptSetTitle ||
        'Prompt set in progress';

      promptSetsInProgress.push({
        title,
        assignedAtFormatted: fmtDate(assignment.createdAt || assignment.assignedAt)
      });
    }

    const promptSetsInProgressUnique = [];
    const seenPromptProgress = new Set();

    for (const item of promptSetsInProgress) {
      const key = `${item.title}:${item.assignedAtFormatted}`;
      if (seenPromptProgress.has(key)) continue;
      seenPromptProgress.add(key);
      promptSetsInProgressUnique.push(item);
    }

const nuggetsMonitored = [];

for (const tag of tags || []) {
  const assignedTo = Array.isArray(tag.assignedTo) ? tag.assignedTo : [];

  const teamAssignments = assignedTo.filter(a => {
    const memberId = a?.member?.toString?.() || '';
    return teamPersonIdSet.has(memberId);
  });

  if (!teamAssignments.length) continue;

  const associatedUnits = Array.isArray(tag.associatedUnits) ? tag.associatedUnits : [];

  for (const au of associatedUnits) {
    const unitId = au.item?.toString?.() || au.unitId?.toString?.() || '';
    const unitType = String(au.unitType || au.itemType || '').toLowerCase();

    if (unitType !== 'nugget') continue;
    if (!unitId) continue;

    const nugget = await Nugget.findById(unitId)
      .select('title client region discipline monitoringNotes')
      .lean();

    if (!nugget) continue;

    const teamMonitoringNotes = Array.isArray(nugget.monitoringNotes)
      ? nugget.monitoringNotes.filter(note => {
          const addedBy = note.addedBy?.toString?.() || '';
          return teamPersonIdSet.has(addedBy);
        })
      : [];

    const lastNote = teamMonitoringNotes
      .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))[0];

    nuggetsMonitored.push({
      title: nugget.title || tag.tagName || 'Nugget',
      client: nugget.client || '',
      region: nugget.region || '',
      discipline: nugget.discipline || '',
      assignedAtFormatted: fmtDate(tag.createdAt || tag.updatedAt),
      lastMonitoredFormatted: fmtDate(lastNote?.createdAt),
      viewPath: viewPathForUnit('nugget', unitId)
    });
  }
}

const nuggetsMonitoredUnique = [];
const seenNuggets = new Set();

for (const nugget of nuggetsMonitored) {
  const key = `${nugget.title}:${nugget.viewPath}`;
  if (seenNuggets.has(key)) continue;
  seenNuggets.add(key);
  nuggetsMonitoredUnique.push(nugget);
}

    const missionLookup = new Map(
      (missions || []).map(m => [m._id.toString(), m])
    );

    const missionsCompleted = [];
    const missionBadgesEarned = [];



    function missionsBadgesEarnedSafePush(badge) {
  const key = `${badge.badgeName}:${badge.badgeImage}`;
  if (!missionsBadgesEarnedSafePush.seen) {
    missionsBadgesEarnedSafePush.seen = new Set();
  }

  if (missionsBadgesEarnedSafePush.seen.has(key)) return;
  missionsBadgesEarnedSafePush.seen.add(key);
  missionBadgesEarned.push(badge);
}

const missionsInProgress = [];

for (const tag of tags || []) {
  const assignedTo = Array.isArray(tag.assignedTo) ? tag.assignedTo : [];

  const teamAssignments = assignedTo.filter(a => {
    const memberId = a?.member?.toString?.() || '';
    return teamPersonIdSet.has(memberId);
  });

  if (!teamAssignments.length) continue;

  const associatedUnits = Array.isArray(tag.associatedUnits) ? tag.associatedUnits : [];

  for (const au of associatedUnits) {
    const unitId = au.item?.toString?.() || au.unitId?.toString?.() || '';
    const unitType = String(au.unitType || au.itemType || '').toLowerCase();

    if (unitType !== 'mission') continue;
    if (!unitId) continue;

    const mission = missionLookup.get(unitId);
    const title = mission?.mission_title || tag.tagName || 'Mission';

    for (const assignmentRow of teamAssignments) {
      if (assignmentRow.completedAt) {
        missionsCompleted.push({
          title,
          completedAtFormatted: fmtDate(assignmentRow.completedAt),
          viewPath: viewPathForUnit('mission', unitId)
        });

        missionsBadgesEarnedSafePush({
          badgeName: mission?.badge_name || title || 'mission badge',
          badgeImage:
            mission?.badgeImagePath ||
            mission?.badge_image ||
            mission?.badgeImage ||
            ''
        });
      } else {
        missionsInProgress.push({
          title,
          assignedAtFormatted: fmtDate(tag.createdAt || tag.updatedAt),
          viewPath: viewPathForUnit('mission', unitId)
        });
      }
    }
  }
}

    const allTopics = [...topicsFromCompletions, ...topicsFromCompletedUnits].filter(Boolean);

    const freq = new Map();
    for (const topic of allTopics) {
      freq.set(topic, (freq.get(topic) || 0) + 1);
    }

    const topTopics = Array.from(freq.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([topic]) => topic);

    reports.push({
      teamId: leaderIdStr,
      teamName: leader.groupName || 'Unnamed group',
      groupImage: groupImgByLeaderId.get(leaderIdStr) || '/images/default-group.png',

      teamLeaderName: leader.groupLeaderName || leader.name || 'Leader',
      teamLeaderImage:
        leaderImgByLeaderId.get(leaderIdStr) ||
        leader.profileImage ||
        '/images/default-avatar.png',

      memberCount: memberIds.length,

      topTopics,
      unitsCompleted,
      incompleteUnits: incompleteUnitsUnique,

      promptSetsCompleted,
      promptSetBadgesEarned: promptSetBadgesUnique,
      promptSetsInProgress: promptSetsInProgressUnique,

nuggetsMonitored: nuggetsMonitoredUnique,

      missionsInProgress,
      missionsCompleted,
      missionBadgesEarned
    });
  }

  reports.sort((a, b) => {
    const aScore =
      (a.unitsCompleted?.length || 0) +
      (a.promptSetsCompleted?.length || 0) +
      (a.nuggetsMonitored?.length || 0) +
      (a.missionsCompleted?.length || 0);

    const bScore =
      (b.unitsCompleted?.length || 0) +
      (b.promptSetsCompleted?.length || 0) +
      (b.nuggetsMonitored?.length || 0) +
      (b.missionsCompleted?.length || 0);

    if (bScore !== aScore) return bScore - aScore;
    return (a.teamName || '').localeCompare(b.teamName || '');
  });

  return reports;
}

// Build all data needed for ALL admin tabs, every time (no flash, no missing vars)
async function buildAdminPayload(orgId, adminId) {
  const [
    orgSnapshot,
    orgGroups,
    organization,
    adminTeamEngagementReports,
    seenSuggestionsCount
  ] = await Promise.all([
    buildOrgSnapshot(orgId),
    buildOrgGroupsLeaders(orgId),
    Organization.findById(orgId).select('name slug industry createdAt').lean(),
    buildAdminTeamEngagement(orgId),

    // TAB 4: learning suggestions
    // Trigger = a suggestion sent by this admin has been seen / acknowledged by a leader
    UnitSuggestion.countDocuments({
      organization: orgId,
      suggestedBy: adminId,
      $or: [
        { status: 'acknowledged' },
        { acknowledgedAt: { $exists: true, $ne: null } },
        { seenAt: { $exists: true, $ne: null } }
      ]
    })
  ]);

  const counts = orgSnapshot?.counts || {
    leaders: 0,
    groups: 0,
    members: 0,
    pendingJoinRequests: 0,
    pendingLibrarySubmissions: 0,
    suggestionsSent: 0
  };

  // ---------- ADMIN TAB COUNTS: DOT TRIGGERS ONLY ----------
  // TAB 3: requests from leaders to join
  // Trigger = a new pending join request
  const pendingJoinRequestsCount = Number(counts.pendingJoinRequests || 0);

  // TAB 4: learning suggestions
  // Trigger = a suggestion sent by this admin has been seen / acknowledged by a leader
  const acknowledgedSuggestionsCount = Number(seenSuggestionsCount || 0);

  // TAB 5: organization's library units
  // Trigger = a new unit has been added
  const companyLibraryCount = Number(counts.pendingLibrarySubmissions || 0);

  const adminCounts = {
    requests: pendingJoinRequestsCount,
    suggestions: acknowledgedSuggestionsCount,
    companyLibrary: companyLibraryCount
  };

  let seenDocAdmin = await DashboardSeen.findOne({
    userId: adminId,
    role: 'org_admin'
  });

  if (!seenDocAdmin) {
    // First time: baseline all tabs to current counts (no dots on first render)
    seenDocAdmin = new DashboardSeen({
      userId: adminId,
      role: 'org_admin',
      tabs: new Map()
    });

    for (const [key, val] of Object.entries(adminCounts)) {
      seenDocAdmin.tabs.set(key, {
        count: val,
        seenAt: new Date()
      });
    }

    await seenDocAdmin.save();
  } else {
    // If new tabs were added later, baseline them once
    let updated = false;

    for (const [key, val] of Object.entries(adminCounts)) {
      if (!seenDocAdmin.tabs?.has(key)) {
        seenDocAdmin.tabs.set(key, {
          count: val,
          seenAt: new Date()
        });
        updated = true;
      }
    }

    if (updated) {
      await seenDocAdmin.save();
    }
  }

  // Compute badges: show dot ONLY if current > lastSeen
  const adminBadges = {};

  for (const [key, val] of Object.entries(adminCounts)) {
    const last = seenDocAdmin.tabs?.get(key)?.count ?? val;
    adminBadges[key] = val > last;
  }

  return {
    orgSnapshot,

    counts,
    learningFootprint: orgSnapshot?.learningFootprint || {
      activeLearners: 0,
      unitsCompleted: 0,
      promptSetsCompleted: 0,
      avgCompletionsPerLearner: 0,
      mostPopularTopic: '—'
    },
    pendingJoinRequestsList: orgSnapshot?.pendingJoinRequestsList || [],

    organization,
    orgGroups,
    adminTeamEngagementReports,

    adminCounts,
    adminBadges
  };
}





// -----------------------------
// Controller
// -----------------------------
const orgadminController = {
async myOrganization(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
const payload = await buildAdminPayload(orgId, adminId);

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'my-organization',
      ...payload
    });
  } catch (err) {
    console.error('Org admin myOrganization error:', err);
    return next(err);
  }
},

async groupsLeaders(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
const payload = await buildAdminPayload(orgId, adminId);

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'groups-leaders',
      ...payload
    });
  } catch (err) {
    console.error('Org admin groupsLeaders error:', err);
    return next(err);
  }
},

async requests(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
const payload = await buildAdminPayload(orgId, adminId);

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'requests',
      ...payload
    });
  } catch (err) {
    console.error('Org admin requests error:', err);
    return next(err);
  }
},

async suggestions(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
    if (!adminId) return res.redirect('/dashboard/leader');

    const payload = await buildAdminPayload(orgId, adminId);

    const rawMySuggestions = await UnitSuggestion.find({
      organization: orgId,
      suggestedBy: adminId
    })
      .sort({ createdAt: -1 })
      .lean();

    const leaderIds = [...new Set(
      rawMySuggestions
        .map(s => s.leaderId?.toString?.())
        .filter(Boolean)
    )];

    const leaders = leaderIds.length
      ? await Leader.find({ _id: { $in: leaderIds } })
          .select('_id groupLeaderName username groupName')
          .lean()
      : [];

    const leaderNameById = new Map(
      leaders.map(l => [
        l._id.toString(),
        (l.groupLeaderName || l.username || l.groupName || 'Leader')
      ])
    );

    const mySuggestions = rawMySuggestions.map(s => {
      const leaderIdStr = s.leaderId?.toString?.() || '';
      const leaderName = leaderIdStr ? (leaderNameById.get(leaderIdStr) || 'Leader') : '';

      const hasUnit = Boolean(s.unitId);
      const viewPath = hasUnit ? viewPathForUnit(s.unitType, s.unitId) : null;

      const acknowledgedAt = s.acknowledgedAt || s.seenAt || null;
      const isAcknowledged = Boolean(acknowledgedAt) || s.status === 'acknowledged';

      return {
        _id: s._id.toString(),
        unitType: s.unitType,
        unitTitle: s.unitTitle || 'Untitled unit',
        main_topic: s.main_topic || '',
        secondary_topic: s.secondary_topic || '',
        note: s.note || '',
        status: s.status || 'pending',
        suggestedAtFormatted: s.createdAt ? fmtDate(s.createdAt) : '',
        viewPath,
        leaderId: leaderIdStr,
        suggestedToNames: leaderName ? [leaderName] : [],
        isAcknowledged,
        acknowledgedAtFormatted: acknowledgedAt ? fmtDate(acknowledgedAt) : ''
      };
    });

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'suggestions',
      ...payload,
      mySuggestions
    });
  } catch (err) {
    console.error('Org admin suggestions error:', err);
    return next(err);
  }
},




async companyLibrary(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
const payload = await buildAdminPayload(orgId, adminId);
    const orgLeaderLibraries = await buildOrgLeaderLibraries(orgId);

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'company-library',
      ...payload,
      orgLeaderLibraries
    });
  } catch (err) {
    console.error('Org admin companyLibrary error:', err);
    return next(err);
  }
},


async reports(req, res, next) {
  try {
    const orgId = await getOrgIdForAdmin(req);
    if (!orgId) return res.redirect('/dashboard/leader');

    const adminId = req.user?._id;
const payload = await buildAdminPayload(orgId, adminId);

    return res.render('leader_dashboard', {
      ...(await baseRenderData(req)),
      adminTab: 'reports',
      ...payload
    });
  } catch (err) {
    console.error('Org admin reports error:', err);
    return next(err);
  }
},

async markAdminTabSeen(req, res) {
  try {
    const adminId = req.user?._id || req.user?.id;
    if (!adminId) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    const tabKey = req.body?.tab || req.body?.tabKey;
    const currentCount = req.body?.count ?? req.body?.currentCount;

    if (!tabKey) {
      return res.status(400).json({ ok: false, error: 'missing tab key' });
    }

    let seenDoc = await DashboardSeen.findOne({
      userId: adminId,
      role: 'org_admin'
    });

    if (!seenDoc) {
      seenDoc = new DashboardSeen({
        userId: adminId,
        role: 'org_admin',
        tabs: new Map()
      });
    }

    seenDoc.tabs.set(tabKey, {
      count: Number(currentCount) || 0,
      seenAt: new Date()
    });

    await seenDoc.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error('markAdminTabSeen error:', err);
    return res.status(500).json({ ok: false });
  }
},

  // ADMIN: Approve a join request
  async approveJoinRequest(req, res) {
    const back = '/dashboard/leader/org-admin/my-organization';

    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect(`${back}?msg=req-not-found`);
      if (jr.status !== 'pending') return res.redirect(`${back}?msg=req-not-pending`);

      const leader = await Leader.findById(jr.leader);
      if (!leader) return res.redirect(`${back}?msg=leader-not-found`);

      leader.organization = jr.organization;
      leader.organizationOptOut = false;

      const org = await Organization.findById(jr.organization).select('name').lean();
      if (org?.name) leader.organizationName = org.name;

      await leader.save();

      await GroupProfile.updateOne(
        { groupId: leader._id },
        { $set: { organization: jr.organization } }
      );

      jr.status = 'approved';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect(`${back}?msg=approved`);
    } catch (err) {
      console.error('approveJoinRequest error:', err);
      return res.redirect(`${back}?msg=approve-error`);
    }
  },

  // ADMIN: Reject a join request
  async rejectJoinRequest(req, res) {
    const back = '/dashboard/leader/org-admin/my-organization';

    try {
      const adminId = req.user?._id;
      const { requestId } = req.params;

      const jr = await OrganizationJoinRequest.findById(requestId);
      if (!jr) return res.redirect(`${back}?msg=req-not-found`);
      if (jr.status !== 'pending') return res.redirect(`${back}?msg=req-not-pending`);

      jr.status = 'rejected';
      jr.reviewedAt = new Date();
      jr.reviewedBy = adminId;
      jr.note = String(req.body.note || '').trim();
      await jr.save();

      return res.redirect(`${back}?msg=rejected`);
    } catch (err) {
      console.error('rejectJoinRequest error:', err);
      return res.redirect(`${back}?msg=reject-error`);
    }
  }
};

module.exports = orgadminController;

