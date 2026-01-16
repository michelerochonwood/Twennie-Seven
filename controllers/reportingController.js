const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const GroupMember = require('../models/member_models/group_member');
const Leader = require('../models/member_models/leader');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const Notes = require('../models/notes/notes');
const { toCSV } = require('../utils/csv');
const Mission = require('../models/unit_models/mission');
const Upcoming = require('../models/unit_models/upcoming');
const Nugget   = require('../models/unit_models/nugget');




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


const fetchContributedUnits = async (memberId) => {
    const [articles, videos, interviews, exercises, templates, promptSets] = await Promise.all([
        Article.find({ "author.id": memberId }).select("article_title main_topic secondary_topics").lean(),
        Video.find({ "author.id": memberId }).select("video_title main_topic secondary_topics").lean(),
        Interview.find({ "author.id": memberId }).select("interview_title main_topic secondary_topics").lean(),
        Exercise.find({ "author.id": memberId }).select("exercise_title main_topic secondary_topics").lean(),
        Template.find({ "author.id": memberId }).select("template_title main_topic secondary_topics").lean(),
        PromptSet.find({ "author.id": memberId }).select("promptset_title main_topic secondary_topics").lean()
    ]);

    return [
        ...articles.map(unit => ({
            unitTitle: unit.article_title,
            unitType: "Article",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        })),
        ...videos.map(unit => ({
            unitTitle: unit.video_title,
            unitType: "Video",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        })),
        ...interviews.map(unit => ({
            unitTitle: unit.interview_title,
            unitType: "Interview",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        })),
        ...exercises.map(unit => ({
            unitTitle: unit.exercise_title,
            unitType: "Exercise",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        })),
        ...templates.map(unit => ({
            unitTitle: unit.template_title,
            unitType: "Template",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        })),
        ...promptSets.map(unit => ({
            unitTitle: unit.promptset_title,
            unitType: "Prompt Set",
            main_topic: unit.main_topic,
            secondary_topics: unit.secondary_topics || []
        }))
    ];
};

// ✅ Fetch Member Engagement Report
// ✅ Member Engagement (per-member rows shaped for the view)

// - Missions NEVER appear under unitsCompleted (even if Notes.unitType is missing/wrong)
// - Uses resolveUnitDetails() as source of truth for mission detection
// - Keeps mission topics included in topicsEngaged
const getMemberEngagementReport = async (req, res) => {
  try {
    console.log("✅ Fetching Member Engagement Report (mission-safe)…");

    // Normalize leader id
    const leaderId = (req.user?._id || req.user?.id || req.session?.user?.id)?.toString();
    console.log(
      "[memberengagement] leaderId:",
      leaderId,
      "req.user.id:",
      req.user?.id,
      "req.user._id:",
      req.user?._id
    );

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    // 1) Leader for header + member list source of truth
    const leaderDoc = await Leader.findById(leaderId).select("groupName members").lean();
    if (!leaderDoc) {
      console.error("❌ Leader not found:", leaderId);
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    // 2) Members of this leader’s group (use leader.members)
    const memberIdsFromLeader = Array.isArray(leaderDoc.members) ? leaderDoc.members : [];
    console.log("[memberengagement] leader.members length:", memberIdsFromLeader.length);

    const members = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    console.log("[memberengagement] group members (from leader.members):", members.length);

    if (!members.length) {
      return res.render("report_views/memberengagement", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isMemberEngagement: true,
        memberEngagementReports: []
      });
    }

    const memberIds = members.map(m => m._id);
    const nameById = new Map(members.map(m => [m._id.toString(), m.name]));

    // 3) Bulk pulls
    const [promptCompletions, notes, missions] = await Promise.all([
      PromptSetCompletion.find({ memberId: { $in: memberIds } })
        .populate("promptSetId", "promptset_title main_topic secondary_topics")
        .lean(),

      Notes.find({ memberID: { $in: memberIds } }).lean(),

      // Used for stable title lookup / fallback
      Mission.find({}).select("_id mission_title main_topic secondary_topics").lean()
    ]);

    const missionTitleById = new Map(
      (missions || []).map(m => [m._id.toString(), m.mission_title || "Untitled mission"])
    );

    const missionTopicsById = new Map(
      (missions || []).map(m => [
        m._id.toString(),
        {
          main: m.main_topic || "",
          secondary: Array.isArray(m.secondary_topics) ? m.secondary_topics : []
        }
      ])
    );

    // Group prompt completions by member
    const completionsByMember = new Map();
    for (const c of (promptCompletions || [])) {
      const key = c.memberId?.toString?.() || "";
      if (!key) continue;
      if (!completionsByMember.has(key)) completionsByMember.set(key, []);
      completionsByMember.get(key).push(c);
    }

    // Group notes by member
    const notesByMember = new Map();
    for (const n of (notes || [])) {
      const key = n.memberID?.toString?.() || "";
      if (!key) continue;
      if (!notesByMember.has(key)) notesByMember.set(key, []);
      notesByMember.get(key).push(n);
    }

    // 4) Build rows per member
    const memberEngagementReports = [];

    for (const m of members) {
      const mid = m._id.toString();

      // Prompt sets completed
      const myComps = completionsByMember.get(mid) || [];
      const promptSetsCompleted = myComps
        .map(c => ({
          name: c.promptSetId?.promptset_title || "Unknown Prompt Set",
          dateCompleted: c.completedAt || c.createdAt
        }))
        .sort((a, b) => new Date(a.dateCompleted || 0) - new Date(b.dateCompleted || 0));

      // Notes = units completed + missions completed + topics
      const myNotes = notesByMember.get(mid) || [];
      const unitsCompleted = [];
      const topicsFromCompleted = [];

      const missionIdSet = new Set();
      const missionsCompleted = [];

      for (const n of myNotes) {
        const unitIdStr = n.unitID?.toString?.() || "";
        if (!unitIdStr) continue;

        // ✅ Resolve what this note actually points to (mission-safe)
        const d = await resolveUnitDetails(unitIdStr);
        const resolvedType = String(d.unitType || "").toLowerCase();

        // ✅ If it resolves to a mission, route to missionsCompleted no matter what Notes.unitType says
        if (resolvedType === "mission") {
          if (!missionIdSet.has(unitIdStr)) {
            missionIdSet.add(unitIdStr);
            missionsCompleted.push({
              missionId: unitIdStr,
              missionTitle: missionTitleById.get(unitIdStr) || d.unitTitle || "Untitled mission"
            });
          }

          // Include mission topics in topics engaged
          const mt = missionTopicsById.get(unitIdStr);
          if (mt?.main) topicsFromCompleted.push(mt.main);
          if (Array.isArray(mt?.secondary) && mt.secondary.length) topicsFromCompleted.push(...mt.secondary);

          // Fallback: if missionTopicsById didn't have it (e.g., newly added), use resolved details
          if (!mt?.main && d.main_topic) topicsFromCompleted.push(d.main_topic);
          if ((!mt?.secondary || !mt.secondary.length) && Array.isArray(d.secondary_topics) && d.secondary_topics.length) {
            topicsFromCompleted.push(...d.secondary_topics);
          }

          continue; // ✅ critical: keeps missions out of unitsCompleted
        }

        // ✅ Otherwise: normal unit completion
        unitsCompleted.push({ unitTitle: d.unitTitle, unitType: d.unitType });

        if (d.main_topic) topicsFromCompleted.push(d.main_topic);
        if (Array.isArray(d.secondary_topics) && d.secondary_topics.length) {
          topicsFromCompleted.push(...d.secondary_topics);
        }
      }

      unitsCompleted.sort((a, b) => (a.unitTitle || "").localeCompare(b.unitTitle || ""));
      missionsCompleted.sort((a, b) => (a.missionTitle || "").localeCompare(b.missionTitle || ""));

      // Topics from prompt completions
      const topicsFromComps = myComps.flatMap(c => {
        const main = c.promptSetId?.main_topic ? [c.promptSetId.main_topic] : [];
        const secs = Array.isArray(c.promptSetId?.secondary_topics) ? c.promptSetId.secondary_topics : [];
        return [...main, ...secs];
      });

      const topicsEngaged = Array.from(
        new Set([...topicsFromComps, ...topicsFromCompleted].filter(Boolean))
      ).sort((a, b) => a.localeCompare(b));

      memberEngagementReports.push({
        memberName: nameById.get(mid) || "Unknown Member",
        unitsCompleted,
        promptSetsCompleted,
        missionsCompleted,
        topicsEngaged
      });
    }

    console.log("[memberengagement] rows:", memberEngagementReports.length);
    if (memberEngagementReports[0]) console.log("[memberengagement] sample row:", memberEngagementReports[0]);

    return res.render("report_views/memberengagement", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      isMemberEngagement: true,
      memberEngagementReports
    });
  } catch (err) {
    console.error("❌ Error loading Member Engagement Report:", err);
    return res.status(500).send("Server error");
  }
};





// ✅ Fetch Prompt Sets Completed Report
// ✅ Leader: Prompt Sets Completed (progress-driven, with completion fallback)
const getPromptSetsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Prompt Sets Completed Report (from PROGRESS)…");

    // 0) Leader + group members
    const leader = await Leader.findById(req.user.id).select("groupName").lean();
    if (!leader) {
      console.error("❌ Leader not found.");
      return res.status(403).json({ error: "Access denied", message: "Leader not found." });
    }

    const members = await GroupMember.find({ groupId: req.user.id })
      .select("_id name")
      .lean();

    const memberIds = members.map(m => m._id?.toString());
    const nameById = new Map(members.map(m => [m._id.toString(), m.name]));

    // 1) Pull all PROGRESS rows for this team (source of truth for notes)
    const progresses = await PromptSetProgress.find({ memberId: { $in: memberIds } })
      .populate("promptSetId")
      .lean();

    // 2) Pull COMPLETIONS once (to get completedAt if it exists)
    const completions = await PromptSetCompletion.find({ memberId: { $in: memberIds } })
      .select("memberId promptSetId completedAt notes")
      .lean();

    const completionKey = (mid, psid) => `${mid}::${psid}`;
    const completionByKey = new Map(
      completions.map(c => [completionKey(c.memberId.toString(), c.promptSetId.toString()), c])
    );

    const TOTAL_PROMPTS = 21; // Prompt0 + Prompts 1..20
    const reports = [];

    for (const p of progresses) {
      const ps = p.promptSetId;
      if (!ps) continue; // guard

      const mid = p.memberId?.toString();
      const memberName = nameById.get(mid) || "Unknown Member";

      // Prompts: build 21 columns from PromptSet fields (0..20)
      const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
        const headlineKey = `prompt_headline${idx}`;
        const textKey     = `Prompt${idx}`;
        return {
          promptHeadline: ps?.[headlineKey] || `Prompt ${idx === 0 ? 1 : idx + 1}`,
          promptText: ps?.[textKey] || ""
        };
      });

      // Notes from progress; pad to 21; shape to { notes: [{content}] }
      const notesArr = Array.isArray(p.notes) ? p.notes : [];
      const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
        const content = notesArr[idx] || "";
        return { notes: content ? [{ memberName, content }] : [] };
      });

      // Completion fallback for date
      const comp = completionByKey.get(completionKey(mid, ps._id.toString()));
      const dateCompleted = comp?.completedAt || p.updatedAt || p.createdAt;

      reports.push({
        // Overview table
        promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
        main_topic: ps.main_topic || "No Topic",
        secondary_topics: ps.secondary_topics || [],
        purpose: ps.purpose || "No purpose provided",
        characteristics: ps.characteristics || [],
        targetAudience: ps.target_audience || "No audience specified",

        // Who/when
        completedBy: [{ memberName, dateCompleted }],

        // Prompt texts & notes tables
        prompts,
        promptNotes
      });
    }

    // Optional: sort by Prompt Set Title then member
    reports.sort((a, b) => {
      const t = a.promptSetTitle.localeCompare(b.promptSetTitle);
      if (t !== 0) return t;
      const an = a.completedBy?.[0]?.memberName || "";
      const bn = b.completedBy?.[0]?.memberName || "";
      return an.localeCompare(bn);
    });

    return res.render("report_views/promptsetscompleted", {
      layout: "dashboardlayout",
      leaderGroupName: leader.groupName,
      promptSetsCompletedReports: reports
    });
  } catch (err) {
    console.error("❌ Error loading Prompt Sets Completed Report (progress-driven):", err);
    return res.status(500).send("Server error");
  }
};









const getTeamEngagementReport = async (req, res) => {
  try {
    console.log("✅ Fetching Team Engagement Report (progress/completion aggregated)…");

    // 1) Leader
    const leader = await Leader.findById(req.user.id).select("groupName").lean();
    if (!leader) {
      console.error("❌ Leader not found for user ID:", req.user.id);
      return res.status(403).json({ error: "Access denied", message: "Leader not found." });
    }

    // 2) Team members (IDs only)
    const members = await GroupMember.find({ groupId: req.user.id })
      .select("_id name")
      .lean();
    const memberIds = members.map(m => m._id);
    if (!memberIds.length) {
      console.warn("⚠️ No group members found for this leader.");
      return res.render("report_views/teamengagement", {
        layout: "dashboardlayout",
        leaderGroupName: leader.groupName,
        teamEngagementReports: [{
          promptSetsCompleted: [],
          badgesEarned: [],
          unitsCompleted: [],
          unitsContributed: [],
          topicsEngaged: []
        }]
      });
    }

    // 3) Prompt set COMPLETIONS for the team (names + badges + topics)
    const promptCompletions = await PromptSetCompletion
      .find({ memberId: { $in: memberIds } })
      .populate("promptSetId", "promptset_title main_topic secondary_topics")
      .lean();

    const promptSetsCompleted = promptCompletions.map(p => ({
      name: p.promptSetId?.promptset_title || "Unknown Prompt Set",
      dateCompleted: p.completedAt || p.createdAt
    }));

    const badgesEarned = promptCompletions.flatMap(p => {
      const img = p.earnedBadge?.image;
      const nm  = p.earnedBadge?.name;
      return (img || nm) ? [{ badgeImage: img || "/images/default-badge.png", badgeName: nm || "a Twennie Badge" }] : [];
    });

    // For topicsEngaged later
    const topicsFromCompletions = promptCompletions.flatMap(p => {
      const main = p.promptSetId?.main_topic ? [p.promptSetId.main_topic] : [];
      const secs = Array.isArray(p.promptSetId?.secondary_topics) ? p.promptSetId.secondary_topics : [];
      return [...main, ...secs];
    });

    // 4) UNITS COMPLETED (Notes) for the team
    const notes = await Notes.find({ memberID: { $in: memberIds } }).lean();

    // Resolve each noted unit's details (title/type/topics)
    const unitsCompleted = await Promise.all(notes.map(async (n) => {
      const d = await resolveUnitDetails(n.unitID);
      return {
        unitTitle: d.unitTitle,
        unitType: d.unitType,
        main_topic: d.main_topic,
        secondary_topics: d.secondary_topics || []
      };
    }));

    const topicsFromCompletedUnits = unitsCompleted.flatMap(u => {
      const main = u.main_topic ? [u.main_topic] : [];
      const secs = Array.isArray(u.secondary_topics) ? u.secondary_topics : [];
      return [...main, ...secs];
    });

    // 5) UNITS CONTRIBUTED (authored by team members)
    // Bulk fetch by author to also get topics (to feed Topics Engaged)
    const [
      articles, videos, interviews, exercises, templates, promptSets
    ] = await Promise.all([
      Article.find({ "author.id": { $in: memberIds } }).select("article_title main_topic secondary_topics").lean(),
      Video.find({ "author.id": { $in: memberIds } }).select("video_title main_topic secondary_topics").lean(),
      Interview.find({ "author.id": { $in: memberIds } }).select("interview_title main_topic secondary_topics").lean(),
      Exercise.find({ "author.id": { $in: memberIds } }).select("exercise_title main_topic secondary_topics").lean(),
      Template.find({ "author.id": { $in: memberIds } }).select("template_title main_topic secondary_topics").lean(),
      PromptSet.find({ "author.id": { $in: memberIds } }).select("promptset_title main_topic secondary_topics").lean()
    ]);

    const unitsContributed = [
      ...articles.map(u => ({ unitTitle: u.article_title, unitType: "Article", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] })),
      ...videos.map(u => ({ unitTitle: u.video_title, unitType: "Video", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] })),
      ...interviews.map(u => ({ unitTitle: u.interview_title, unitType: "Interview", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] })),
      ...exercises.map(u => ({ unitTitle: u.exercise_title, unitType: "Exercise", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] })),
      ...templates.map(u => ({ unitTitle: u.template_title, unitType: "Template", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] })),
      ...promptSets.map(u => ({ unitTitle: u.promptset_title, unitType: "Prompt Set", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] }))
    ];

    const topicsFromContributions = unitsContributed.flatMap(u => {
      const main = u.main_topic ? [u.main_topic] : [];
      const secs = Array.isArray(u.secondary_topics) ? u.secondary_topics : [];
      return [...main, ...secs];
    });

    // 6) Flatten to the exact shapes your view expects
    const unitsCompletedForView = unitsCompleted.map(u => ({
      unitTitle: u.unitTitle,
      unitType: u.unitType
    }));

    const unitsContributedForView = unitsContributed.map(u => ({
      unitTitle: u.unitTitle,
      unitType: u.unitType
    }));

    // Topics engaged: combine & de-duplicate; filter falsy
    const topicsEngaged = Array.from(new Set([
      ...topicsFromCompletions,
      ...topicsFromCompletedUnits,
      ...topicsFromContributions
    ].filter(Boolean)));

    // Optional: sort lists for nicer output
    promptSetsCompleted.sort((a, b) => (a.dateCompleted || 0) - (b.dateCompleted || 0));
    badgesEarned.sort((a, b) => (a.badgeName || "").localeCompare(b.badgeName || ""));
    unitsCompletedForView.sort((a, b) => a.unitTitle.localeCompare(b.unitTitle));
    unitsContributedForView.sort((a, b) => a.unitTitle.localeCompare(b.unitTitle));
    topicsEngaged.sort((a, b) => a.localeCompare(b));

    const teamData = {
      promptSetsCompleted,
      badgesEarned,
      unitsCompleted: unitsCompletedForView,
      unitsContributed: unitsContributedForView,
      topicsEngaged
    };

    return res.render("report_views/teamengagement", {
      layout: "dashboardlayout",
      leaderGroupName: leader.groupName,
      teamEngagementReports: [teamData] // the view iterates this
    });

  } catch (err) {
    console.error("❌ Error loading Team Engagement Report:", err);
    return res.status(500).send("Server error");
  }
};





const getUnitsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Units Completed Report (grouped by unit)…");

    // 1) Leader header
    const leader = await Leader.findById(req.user.id).select("groupName").lean();
    if (!leader) {
      console.error("❌ Leader not found.");
      return res.status(403).json({ error: "Access denied", message: "Leader not found." });
    }

    // 2) Team members
    const members = await GroupMember.find({ groupId: req.user.id })
      .select("_id name")
      .lean();

    const memberIds = members.map(m => m._id);
    const nameById = new Map(members.map(m => [m._id.toString(), m.name]));
    if (!memberIds.length) {
      console.warn("⚠️ No group members found.");
      return res.render("report_views/unitscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leader.groupName,
        unitsCompletedReports: []
      });
    }

    // 3) Fetch all unit completion notes for those members
    const notes = await Notes.find({ memberID: { $in: memberIds } }).lean();

    // 4) Group notes by unitID
    const byUnit = new Map(); // unitID -> { notes: [note], members: Set(memberId) }
    for (const n of notes) {
      const u = (n.unitID || "").toString();
      if (!u) continue;
      if (!byUnit.has(u)) byUnit.set(u, { notes: [], members: new Set() });
      byUnit.get(u).notes.push(n);
      byUnit.get(u).members.add((n.memberID || "").toString());
    }

    // 5) Build report rows per unit
    const unitsCompletedReports = [];
    for (const [unitID, bucket] of byUnit.entries()) {
      // Resolve unit metadata: title / type / topics
      const details = await resolveUnitDetails(unitID);

      // CompletedBy: each member who has at least one note for this unit (date = earliest note they submitted for this unit)
      const completedBy = [];
      for (const mid of bucket.members) {
        const memberNotesForUnit = bucket.notes.filter(n => String(n.memberID) === mid);
        if (!memberNotesForUnit.length) continue;
        const firstDate = memberNotesForUnit
          .map(n => n.createdAt || n.updatedAt)
          .filter(Boolean)
          .sort((a, b) => new Date(a) - new Date(b))[0];
        completedBy.push({
          memberName: nameById.get(mid) || "Unknown Member",
          dateCompleted: firstDate || new Date(0)
        });
      }

      // MemberNotes: flatten all notes (each row expects an array of { notes: [{content, dateSubmitted}] })
      // Your table iterates memberNotes -> notes -> content/dateSubmitted
      const memberNotes = [];
      for (const n of bucket.notes) {
        memberNotes.push({
          notes: [{
            content: n.note_content || "",
            dateSubmitted: n.createdAt || n.updatedAt || null
          }]
        });
      }

      unitsCompletedReports.push({
        unitTitle: details.unitTitle,
        unitType: details.unitType,
        main_topic: details.main_topic,
        secondary_topics: details.secondary_topics || [],
        completedBy: completedBy.sort((a, b) => (a.dateCompleted || 0) - (b.dateCompleted || 0)),
        memberNotes: memberNotes.sort((a, b) => {
          const da = a.notes?.[0]?.dateSubmitted ? new Date(a.notes[0].dateSubmitted) : 0;
          const db = b.notes?.[0]?.dateSubmitted ? new Date(b.notes[0].dateSubmitted) : 0;
          return da - db;
        })
      });
    }

    // Optional: sort units alphabetically
    unitsCompletedReports.sort((a, b) => a.unitTitle.localeCompare(b.unitTitle));

    return res.render("report_views/unitscompleted", {
      layout: "dashboardlayout",
      leaderGroupName: leader.groupName,
      unitsCompletedReports
    });

  } catch (err) {
    console.error("❌ Error loading Units Completed Report:", err);
    return res.status(500).send("Server error");
  }
};



const TOTAL_PROMPTS = 21; // Prompt0 + Prompts 1..20

const getIndividualPromptSetCompletionReport = async (req, res) => {
  try {
    console.log("✅ Fetching Individual Prompt Set Report from PROGRESS...");

    const memberId = req.user._id;
    const TOTAL_PROMPTS = 21; // Prompt0 + Prompts 1..20

    // Pull all progress rows for this member (source of truth for notes)
    const progresses = await PromptSetProgress.find({ memberId })
      .populate('promptSetId')
      .lean();

    const reportData = progresses
      .filter(p => !!p.promptSetId) // guard missing PS
      .map(p => {
        const ps = p.promptSetId;

        // Build the 21 prompt descriptors from the PromptSet doc.
        // We render 21 columns labeled 1..21 in the view; internally we map:
        // column 1 → Prompt0, column 2 → Prompt1, ... column 21 → Prompt20
        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, col) => {
          const idx = col === 0 ? 0 : col; // col=0→0, col=20→20 (1-based view, 0-based storage)
          const headlineKey = `prompt_headline${idx}`;
          const textKey     = `Prompt${idx}`;
          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${col + 1}`,
            promptText: ps?.[textKey] || ''
          };
        });

        // Notes from progress; pad to 21
        const notes = Array.isArray(p.notes) ? p.notes : [];
        const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, col) => {
          const idx = col === 0 ? 0 : col; // same mapping as above
          const content = notes[idx] || '';
          return {
            promptNumber: `Prompt ${col + 1}`,
            notes: content ? [{ content }] : []
          };
        });

        return {
          promptSetTitle: ps.promptset_title,
          main_topic: ps.main_topic,
          secondary_topics: ps.secondary_topics || [],
          purpose: ps.purpose || "No purpose provided",
          characteristics: ps.characteristics || [],
          targetAudience: ps.target_audience || "No audience specified",
          // We don't have an actual completion date here; use updatedAt as a proxy
          dateCompleted: p.updatedAt || p.createdAt,

          prompts,      // for the “Prompt Texts” row
          promptNotes   // for the “Your Notes” row
        };
      });

    return res.render("report_views/individual_promptsets_completed", {
      layout: "dashboardlayout",
      promptSetsCompletedReports: reportData
    });

  } catch (err) {
    console.error("❌ Error loading individual prompt set report (from progress):", err);
    return res.status(500).render("member_form_views/error", {
      layout: "memberformlayout",
      title: "Report Error",
      errorMessage: "We couldn't load your prompt set report. Please try again later."
    });
  }
};


const getGroupMemberPromptSetCompletionReport = async (req, res) => {
  try {
    console.log("✅ Fetching Group Member Prompt Set Report from PROGRESS...");

    const memberId = req.user._id;
    const TOTAL_PROMPTS = 21; // Prompt0 + Prompts 1..20

    // Pull all progress rows for this member (source of truth for notes)
    const progresses = await PromptSetProgress.find({ memberId })
      .populate('promptSetId')
      .lean();

    const reportData = progresses
      .filter(p => !!p.promptSetId)
      .map(p => {
        const ps = p.promptSetId;

        // Build 21 prompt descriptors (view shows 1..21; map to 0..20 internally)
        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, col) => {
          const idx = col === 0 ? 0 : col;
          const headlineKey = `prompt_headline${idx}`;
          const textKey     = `Prompt${idx}`;
          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${col + 1}`,
            promptText: ps?.[textKey] || ''
          };
        });

        // Notes from progress; pad to 21
        const notes = Array.isArray(p.notes) ? p.notes : [];
        const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, col) => {
          const idx = col === 0 ? 0 : col;
          const content = notes[idx] || '';
          return {
            promptNumber: `Prompt ${col + 1}`,
            notes: content ? [{ content }] : []
          };
        });

        return {
          promptSetTitle: ps.promptset_title,
          main_topic: ps.main_topic,
          secondary_topics: ps.secondary_topics || [],
          purpose: ps.purpose || "No purpose provided",
          characteristics: ps.characteristics || [],
          targetAudience: ps.target_audience || "No audience specified",
          dateCompleted: p.updatedAt || p.createdAt,

          prompts,
          promptNotes
        };
      });

    return res.render("report_views/groupmember_promptsets_completed", {
      layout: "dashboardlayout",
      promptSetsCompletedReports: reportData
    });

  } catch (err) {
    console.error("❌ Error loading group member prompt set report (from progress):", err);
    return res.status(500).render("groupmember_form_views/error", {
      layout: "groupmemberformlayout",
      title: "Report Error",
      errorMessage: "We couldn't load your prompt set report. Please try again later."
    });
  }
};

// GET /reports/memberengagement.csv




module.exports = {

  getMemberEngagementReport,
  getPromptSetsCompletedReport,
  getTeamEngagementReport,
  getUnitsCompletedReport,
  getIndividualPromptSetCompletionReport,
getGroupMemberPromptSetCompletionReport
};
