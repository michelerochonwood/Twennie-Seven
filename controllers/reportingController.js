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
const Tag = require('../models/tag'); 




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
// ✅ Member Engagement (per-member rows shaped for the view)
// - Missions NEVER appear under unitsCompleted (even if Notes.unitType is missing/wrong)
// - Uses resolveUnitDetails() as source of truth for mission detection
// - Keeps mission topics included in topicsEngaged
const getMemberEngagementReport = async (req, res) => {
  try {
    console.log("✅ Fetching Member Engagement Report (leader + members)…");

    // -----------------------------
    // Helpers
    // -----------------------------
    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const safeString = (v) => (v == null ? "" : String(v));
    const uniq = (arr) => Array.from(new Set(arr));
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    // -----------------------------
    // Leader identity
    // -----------------------------
    const leaderId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    // IMPORTANT: your leader record uses groupLeaderName, not name
    const leaderDoc = await Leader.findById(leaderId)
      .select("_id groupName groupLeaderName members")
      .lean();

    if (!leaderDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    const leaderName = leaderDoc.groupLeaderName || "Leader";

    // -----------------------------
    // Group members
    // -----------------------------
    const memberIdsFromLeader = safeArray(leaderDoc.members);
    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    // Include leader as a report person + members
    const reportPeople = [
      { _id: leaderDoc._id, name: leaderName },
      ...groupMembers.map(m => ({ _id: m._id, name: m.name || "Group Member" }))
    ];

    const personIds = reportPeople.map(p => p._id);
    const nameById = new Map(reportPeople.map(p => [toIdString(p._id), p.name]));

    // If for some reason we have nobody, render empty safely
    if (!personIds.length) {
      return res.render("report_views/memberengagement", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        leaderName,
        isMemberEngagement: true,
        memberEngagementReports: [],
        groupedUnits: []
      });
    }

    // -----------------------------
    // Fetch all engagement sources
    // -----------------------------
    const [promptCompletions, notes, missions] = await Promise.all([
      PromptSetCompletion.find({ memberId: { $in: personIds } })
        .populate("promptSetId", "promptset_title main_topic secondary_topics")
        .lean(),

      Notes.find({ memberID: { $in: personIds } }).lean(),

      Mission.find({})
        .select("_id mission_title main_topic secondary_topics")
        .lean()
    ]);

    // Mission lookup maps
    const missionTitleById = new Map(
      safeArray(missions).map(m => [toIdString(m._id), m.mission_title || "Untitled mission"])
    );

    const missionTopicsById = new Map(
      safeArray(missions).map(m => [
        toIdString(m._id),
        {
          main: safeString(m.main_topic),
          secondary: safeArray(m.secondary_topics)
        }
      ])
    );

    // -----------------------------
    // Index prompt completions by person
    // -----------------------------
    const completionsByPerson = new Map();
    for (const c of safeArray(promptCompletions)) {
      const key = toIdString(c.memberId);
      if (!key) continue;
      if (!completionsByPerson.has(key)) completionsByPerson.set(key, []);
      completionsByPerson.get(key).push(c);
    }

    // -----------------------------
    // Index notes by person
    // -----------------------------
    const notesByPerson = new Map();
    for (const n of safeArray(notes)) {
      const key = toIdString(n.memberID);
      if (!key) continue;
      if (!notesByPerson.has(key)) notesByPerson.set(key, []);
      notesByPerson.get(key).push(n);
    }

    // -----------------------------
    // Bulk resolve unit details (prevents await inside loops)
    // -----------------------------
    const allUnitIdStrs = uniq(
      safeArray(notes)
        .map(n => toIdString(n.unitID))
        .filter(Boolean)
    );

    const unitDetailsById = new Map();

    await Promise.all(
      allUnitIdStrs.map(async (unitIdStr) => {
        try {
          const d = await resolveUnitDetails(unitIdStr);
          unitDetailsById.set(unitIdStr, d || {});
        } catch (e) {
          console.warn("[memberengagement] resolveUnitDetails failed:", unitIdStr, e?.message);
          unitDetailsById.set(unitIdStr, {});
        }
      })
    );

    // -----------------------------
    // Build per-person report + grouped units
    // -----------------------------
    const memberEngagementReports = [];
    const groupedUnitsMap = new Map(); // unitId -> { unitTitle, unitType, members: [] }

    for (const p of reportPeople) {
      const pid = toIdString(p._id);
      const personName = nameById.get(pid) || "Unknown";

      // Prompt sets completed (and topics from them)
      const myComps = completionsByPerson.get(pid) || [];
      const promptSetsCompleted = myComps
        .map(c => ({
          name: c.promptSetId?.promptset_title || "Unknown Prompt Set",
          dateCompleted: c.completedAt || c.createdAt
        }))
        .sort((a, b) => new Date(a.dateCompleted || 0) - new Date(b.dateCompleted || 0));

      const topicsFromComps = myComps.flatMap(c => {
        const main = c.promptSetId?.main_topic ? [c.promptSetId.main_topic] : [];
        const secs = Array.isArray(c.promptSetId?.secondary_topics) ? c.promptSetId.secondary_topics : [];
        return [...main, ...secs];
      });

      // Notes -> units / missions / topics
      const myNotes = notesByPerson.get(pid) || [];

      const unitSeen = new Set();    // dedupe units per person
      const missionSeen = new Set(); // dedupe missions per person

      const unitsCompleted = [];
      const missionsCompleted = [];
      const topicsFromCompleted = [];

      for (const n of myNotes) {
        const unitIdStr = toIdString(n.unitID);
        if (!unitIdStr) continue;

        const d = unitDetailsById.get(unitIdStr) || {};
        const unitTitle = safeString(d.unitTitle) || "Untitled";
        const unitType = safeString(d.unitType) || "Unit";
        const unitTypeLower = unitType.toLowerCase();

        // Missions
        if (unitTypeLower === "mission") {
          if (!missionSeen.has(unitIdStr)) {
            missionSeen.add(unitIdStr);
            missionsCompleted.push({
              missionId: unitIdStr,
              missionTitle: missionTitleById.get(unitIdStr) || unitTitle || "Untitled mission"
            });
          }

          const mt = missionTopicsById.get(unitIdStr);
          if (mt?.main) topicsFromCompleted.push(mt.main);
          if (Array.isArray(mt?.secondary) && mt.secondary.length) topicsFromCompleted.push(...mt.secondary);

          // fallback topics if mission doc missing
          if (!mt?.main && d.main_topic) topicsFromCompleted.push(d.main_topic);
          if ((!mt?.secondary || !mt.secondary.length) && Array.isArray(d.secondary_topics) && d.secondary_topics.length) {
            topicsFromCompleted.push(...d.secondary_topics);
          }

          continue;
        }

        // Non-mission units
        if (unitSeen.has(unitIdStr)) continue;
        unitSeen.add(unitIdStr);

        unitsCompleted.push({ unitTitle, unitType });

        if (d.main_topic) topicsFromCompleted.push(d.main_topic);
        if (Array.isArray(d.secondary_topics) && d.secondary_topics.length) {
          topicsFromCompleted.push(...d.secondary_topics);
        }

        // Grouped units table (unit appears once, members listed)
        if (!groupedUnitsMap.has(unitIdStr)) {
          groupedUnitsMap.set(unitIdStr, {
            unitTitle,
            unitType,
            members: []
          });
        }
        groupedUnitsMap.get(unitIdStr).members.push(personName);
      }

      unitsCompleted.sort((a, b) => sortAZ(a.unitTitle, b.unitTitle));
      missionsCompleted.sort((a, b) => sortAZ(a.missionTitle, b.missionTitle));

      const topicsEngaged = uniq(
        [...topicsFromComps, ...topicsFromCompleted]
          .map(t => safeString(t).trim())
          .filter(Boolean)
      ).sort(sortAZ);

      memberEngagementReports.push({
        memberName: personName,
        topicsEngaged,
        unitsCompleted,
        promptSetsCompleted,
        missionsCompleted
      });
    }

    const groupedUnits = Array.from(groupedUnitsMap.values())
      .map(u => ({
        ...u,
        members: uniq(u.members).sort(sortAZ)
      }))
      .sort((a, b) => sortAZ(a.unitTitle, b.unitTitle));

    // -----------------------------
    // Render
    // -----------------------------
    return res.render("report_views/memberengagement", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      leaderName,
      isMemberEngagement: true,
      memberEngagementReports,
      groupedUnits
    });
  } catch (err) {
    console.error("❌ Error loading Member Engagement Report:", err);
    return res.status(500).send("Server error");
  }
};






const getNuggetsMonitoredReport = async (req, res) => {
  try {
    console.log("✅ Fetching Nuggets Being Monitored Report…");

    const leaderId = (req.user?._id || req.user?.id || req.session?.user?.id)?.toString();
    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    const leaderDoc = await Leader.findById(leaderId).select("_id name groupName members").lean();
    if (!leaderDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    // Group members (from leader.members as source of truth)
    const memberIdsFromLeader = Array.isArray(leaderDoc.members) ? leaderDoc.members : [];
    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } }).select("_id name").lean()
      : [];

    // People map (leader + members) for name lookup
    const people = [
      { _id: leaderDoc._id, name: leaderDoc.name || "Leader", role: "leader" },
      ...groupMembers.map(m => ({ _id: m._id, name: m.name || "Group Member", role: "member" }))
    ];
    const nameById = new Map(people.map(p => [p._id.toString(), p.name]));
    const roleById = new Map(people.map(p => [p._id.toString(), p.role]));

    // ✅ Find all tags that include nuggets
    // NOTE: if your unitType is stored as "nugget" (lowercase), keep as-is.
    // If you have mixed casing, this will still work if you normalize when saving;
    // otherwise we can broaden it later.
    const nuggetTags = await Tag.find({
      "associatedUnits.unitType": "nugget"
    })
      .select("name createdAt associatedUnits assignedTo")
      .lean();

    if (!nuggetTags.length) {
      return res.render("report_views/nuggetsmonitored", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isNuggetsMonitored: true,
        monitoredNuggets: []
      });
    }

    // Collect all nugget ids referenced by tags
    const nuggetIds = [];
    for (const t of nuggetTags) {
      const units = Array.isArray(t.associatedUnits) ? t.associatedUnits : [];
      for (const u of units) {
        if (String(u.unitType || "").toLowerCase() !== "nugget") continue;
        const id = u.item?.toString?.();
        if (id) nuggetIds.push(id);
      }
    }

    // Bulk fetch nugget details (title + discipline/client/region)
    const uniqueNuggetIds = Array.from(new Set(nuggetIds));
    const nuggets = uniqueNuggetIds.length
      ? await Nugget.find({ _id: { $in: uniqueNuggetIds } })
          .select("title discipline client region")
          .lean()
      : [];

    const nuggetById = new Map(
      nuggets.map(n => [n._id.toString(), n])
    );

    // Build rows: one row per tagged nugget (dedupe across multiple tags)
    // If the same nugget is tagged multiple times, we merge monitors + instructions + choose earliest taggedAt.
    const rowByNuggetId = new Map();

    for (const t of nuggetTags) {
      const tagName = t.name || "Untitled Tag";
      const taggedAt = t.createdAt || null;

      const units = Array.isArray(t.associatedUnits) ? t.associatedUnits : [];
      const assignedTo = Array.isArray(t.assignedTo) ? t.assignedTo : [];

      // Determine monitors + instructions from assignedTo
      const monitors = [];
      const instructions = [];

      for (const a of assignedTo) {
        const mid = a.member?.toString?.();
        if (!mid) continue;

        monitors.push({
          memberName: nameById.get(mid) || "Unknown",
          role: roleById.get(mid) || ""
        });

        if (a.instructions) instructions.push(a.instructions);
      }

      // If nothing assigned, consider the tag creator (leader) as monitoring (optional)
      // This matches your “any tagged nugget is monitored” intent.
      if (!monitors.length) {
        monitors.push({
          memberName: leaderDoc.name || "Leader",
          role: "leader"
        });
      }

      const isAssigned = assignedTo.length > 0;

      for (const u of units) {
        if (String(u.unitType || "").toLowerCase() !== "nugget") continue;
        const nid = u.item?.toString?.();
        if (!nid) continue;

        const nug = nuggetById.get(nid);

        const baseRow = rowByNuggetId.get(nid) || {
          nuggetId: nid,
          nuggetTitle: nug?.title || "Untitled Nugget",
          discipline: nug?.discipline || "",
          client: nug?.client || "",
          region: nug?.region || "",

          tagName: tagName,
          tagDescription: "", // placeholder if you later add it
          taggedAt: taggedAt,

          isAssigned: isAssigned,
          monitoredBy: [],
          instructions: []
        };

        // If the nugget appears under multiple tags:
        // - keep earliest taggedAt
        // - merge monitors/instructions
        if (!baseRow.taggedAt || (taggedAt && new Date(taggedAt) < new Date(baseRow.taggedAt))) {
          baseRow.taggedAt = taggedAt;
        }

        // If you’d rather show the “most recent” tagName, swap comparison above and set tagName accordingly.
        // For now: first/earliest tag name wins.
        if (!baseRow.tagName) baseRow.tagName = tagName;

        // Merge monitors (dedupe by memberName+role)
        const existingMonitorKeys = new Set(
          (baseRow.monitoredBy || []).map(m => `${m.memberName}::${m.role || ""}`)
        );
        for (const m of monitors) {
          const k = `${m.memberName}::${m.role || ""}`;
          if (!existingMonitorKeys.has(k)) {
            existingMonitorKeys.add(k);
            baseRow.monitoredBy.push(m);
          }
        }

        // Merge instructions (dedupe exact strings)
        const instrSet = new Set(baseRow.instructions || []);
        for (const ins of instructions) {
          if (!ins) continue;
          if (!instrSet.has(ins)) {
            instrSet.add(ins);
            baseRow.instructions.push(ins);
          }
        }

        // If any tag instance is assigned, mark assigned
        if (isAssigned) baseRow.isAssigned = true;

        rowByNuggetId.set(nid, baseRow);
      }
    }

    // Final list + sorting
    const monitoredNuggets = Array.from(rowByNuggetId.values())
      .map(r => {
        // Sort monitors/instructions for tidy display
        r.monitoredBy = (r.monitoredBy || []).sort((a, b) => (a.memberName || "").localeCompare(b.memberName || ""));
        r.instructions = (r.instructions || []).sort((a, b) => (a || "").localeCompare(b || ""));
        return r;
      })
      .sort((a, b) => (a.nuggetTitle || "").localeCompare(b.nuggetTitle || ""));

    return res.render("report_views/nuggetsmonitored", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      isNuggetsMonitored: true,
      monitoredNuggets
    });
  } catch (err) {
    console.error("❌ Error loading Nuggets Being Monitored Report:", err);
    return res.status(500).send("Server error");
  }
};


// ✅ Fetch Prompt Sets Completed Report (progress-driven, completion fallback)
// Uses leader.members as source of truth + includes leader as a row source.
const getPromptSetsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Prompt Sets Completed Report (from PROGRESS; leader+members)…");

    const leaderId = (req.user?._id || req.user?.id || req.session?.user?.id)?.toString();
    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    // 1) Leader header + member list source of truth
    const leaderDoc = await Leader.findById(leaderId).select("_id name groupName members").lean();
    if (!leaderDoc) {
      console.error("❌ Leader not found:", leaderId);
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    // 2) Group members from leader.members
    const memberIdsFromLeader = Array.isArray(leaderDoc.members) ? leaderDoc.members : [];
    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    // 3) People included in report (leader + group members)
    const reportPeople = [
      { _id: leaderDoc._id, name: leaderDoc.name || "Leader" },
      ...groupMembers
    ];

    const personIds = reportPeople.map(p => p._id); // ObjectIds
    const nameById = new Map(reportPeople.map(p => [p._id.toString(), p.name]));

    if (!personIds.length) {
      return res.render("report_views/promptsetscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isPromptSetsCompleted: true,
        promptSetsCompletedReports: []
      });
    }

    // 4) Pull PROGRESS rows (source of truth for notes)
    // ✅ IMPORTANT: use ObjectId $in (your completion docs show ObjectId memberId)
    const progresses = await PromptSetProgress.find({ memberId: { $in: personIds } })
      .populate("promptSetId")
      .lean();

    // 5) Pull COMPLETIONS once (for completedAt fallback)
    const completions = await PromptSetCompletion.find({ memberId: { $in: personIds } })
      .select("memberId promptSetId completedAt createdAt updatedAt")
      .lean();

    const completionKey = (mid, psid) => `${mid}::${psid}`;
    const completionByKey = new Map(
      (completions || []).map(c => [
        completionKey(c.memberId.toString(), c.promptSetId.toString()),
        c
      ])
    );

    const TOTAL_PROMPTS = 21; // Prompt0 + Prompts 1..20
    const reports = [];

    for (const p of (progresses || [])) {
      const ps = p.promptSetId;
      if (!ps) continue;

      const mid = p.memberId?.toString?.() || "";
      const memberName = nameById.get(mid) || "Unknown Member";

      // Prompts: 21 columns from PromptSet fields (0..20)
      const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
        const headlineKey = `prompt_headline${idx}`;
        const textKey     = `Prompt${idx}`;
        return {
          promptHeadline: ps?.[headlineKey] || `Prompt ${idx === 0 ? 1 : idx + 1}`,
          promptText: ps?.[textKey] || ""
        };
      });

      // Notes from progress; pad to 21; shape: { notes: [{ memberName, content }] }
      const notesArr = Array.isArray(p.notes) ? p.notes : [];
      const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
        const content = notesArr[idx] || "";
        return { notes: content ? [{ memberName, content }] : [] };
      });

      // Completion fallback for date
      const comp = completionByKey.get(completionKey(mid, ps._id.toString()));
      const dateCompleted = comp?.completedAt || p.updatedAt || p.createdAt;

      reports.push({
        // Table 1 fields (new view uses these)
        promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
        main_topic: ps.main_topic || "No Topic",
        secondary_topics: ps.secondary_topics || [],
        purpose: ps.purpose || "No purpose provided",

        // Still okay to keep (view no longer shows them, but other views may)
        characteristics: ps.characteristics || [],
        targetAudience: ps.target_audience || "No audience specified",

        // Who/when (view iterates completedBy)
        completedBy: [{ memberName, dateCompleted }],

        // Table 2 fields
        prompts,
        promptNotes
      });
    }

    // Sort by Prompt Set Title then member
    reports.sort((a, b) => {
      const t = (a.promptSetTitle || "").localeCompare(b.promptSetTitle || "");
      if (t !== 0) return t;
      const an = a.completedBy?.[0]?.memberName || "";
      const bn = b.completedBy?.[0]?.memberName || "";
      return an.localeCompare(bn);
    });

    return res.render("report_views/promptsetscompleted", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      isPromptSetsCompleted: true,
      promptSetsCompletedReports: reports
    });
  } catch (err) {
    console.error("❌ Error loading Prompt Sets Completed Report (progress-driven; leader+members):", err);
    return res.status(500).send("Server error");
  }
};








// ✅ Fetch Units Completed Report (grouped by unit, includes notes)
// UPDATED to:
// - use leader.members as source of truth (like Member Engagement)
// - include leader as a “person” (optional; harmless if leader has no Notes)
// - EXCLUDE missions from this report (missions are not "library units")
// - keep output shape exactly as the view expects
const getUnitsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Units Completed Report (grouped by unit; leader+members)…");

    const leaderId = (req.user?._id || req.user?.id || req.session?.user?.id)?.toString();
    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    // 1) Leader header + member list source of truth
    const leaderDoc = await Leader.findById(leaderId).select("_id name groupName members").lean();
    if (!leaderDoc) {
      console.error("❌ Leader not found:", leaderId);
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    // 2) Group members from leader.members
    const memberIdsFromLeader = Array.isArray(leaderDoc.members) ? leaderDoc.members : [];
    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    // ✅ Include leader as a report person (optional)
    const reportPeople = [
      { _id: leaderDoc._id, name: leaderDoc.name || "Leader" },
      ...groupMembers
    ];

    const personIds = reportPeople.map(p => p._id);
    const nameById = new Map(reportPeople.map(p => [p._id.toString(), p.name]));

    if (!personIds.length) {
      return res.render("report_views/unitscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isUnitsCompleted: true,
        unitsCompletedReports: []
      });
    }

    // 3) Fetch all completion notes for these people
    // NOTE: Notes uses memberID (capital D) in your existing codebase
    const notes = await Notes.find({ memberID: { $in: personIds } }).lean();

    // 4) Filter OUT mission notes (missions have their own column/report)
    const filteredNotes = (notes || []).filter(n => {
      const t = String(n.unitType || "").toLowerCase();
      return t !== "mission";
    });

    if (!filteredNotes.length) {
      return res.render("report_views/unitscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isUnitsCompleted: true,
        unitsCompletedReports: []
      });
    }

    // 5) Group notes by unitID
    const byUnit = new Map(); // unitID -> { notes: [note], members: Set(memberId) }
    for (const n of filteredNotes) {
      const u = (n.unitID || "").toString();
      if (!u) continue;
      if (!byUnit.has(u)) byUnit.set(u, { notes: [], members: new Set() });
      byUnit.get(u).notes.push(n);
      byUnit.get(u).members.add((n.memberID || "").toString());
    }

    // 6) Build report rows per unit
    const unitsCompletedReports = [];

    for (const [unitID, bucket] of byUnit.entries()) {
      // Resolve unit metadata: title / type / topics
      const details = await resolveUnitDetails(unitID);

      // ✅ Extra guard: if resolve says it's a Mission, skip it (covers bad/missing unitType on Notes)
      if (String(details.unitType || "").toLowerCase() === "mission") continue;

      // CompletedBy: each member who has at least one note for this unit
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

      // MemberNotes: flatten all notes
      // View expects: memberNotes -> notes -> {content, dateSubmitted}
      const memberNotes = bucket.notes
        .map(n => ({
          notes: [{
            content: n.note_content || "",
            dateSubmitted: n.createdAt || n.updatedAt || null
          }]
        }))
        .sort((a, b) => {
          const da = a.notes?.[0]?.dateSubmitted ? new Date(a.notes[0].dateSubmitted) : 0;
          const db = b.notes?.[0]?.dateSubmitted ? new Date(b.notes[0].dateSubmitted) : 0;
          return da - db;
        });

      unitsCompletedReports.push({
        unitTitle: details.unitTitle,
        unitType: details.unitType,
        main_topic: details.main_topic,
        secondary_topics: details.secondary_topics || [],
        completedBy: completedBy.sort((a, b) => new Date(a.dateCompleted || 0) - new Date(b.dateCompleted || 0)),
        memberNotes
      });
    }

    // Optional: sort units alphabetically
    unitsCompletedReports.sort((a, b) => (a.unitTitle || "").localeCompare(b.unitTitle || ""));

    return res.render("report_views/unitscompleted", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      isUnitsCompleted: true,
      unitsCompletedReports
    });
  } catch (err) {
    console.error("❌ Error loading Units Completed Report:", err);
    return res.status(500).send("Server error");
  }
};











module.exports = {
  getMemberEngagementReport,
  getNuggetsMonitoredReport,
  getPromptSetsCompletedReport,
  getUnitsCompletedReport,
};