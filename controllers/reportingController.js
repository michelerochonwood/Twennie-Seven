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






// ✅ Resolve Unit Title & Topics
const resolveUnitDetails = async (unitID) => {
    if (!unitID) return { unitTitle: "Unknown Unit", unitType: "Unknown", main_topic: "Unknown", secondary_topics: [] };

    const unit = await Article.findById(unitID).select("article_title main_topic secondary_topics").lean() ||
                 await Video.findById(unitID).select("video_title main_topic secondary_topics").lean() ||
                 await Interview.findById(unitID).select("interview_title main_topic secondary_topics").lean() ||
                 await Exercise.findById(unitID).select("exercise_title main_topic secondary_topics").lean() ||
                 await Template.findById(unitID).select("template_title main_topic secondary_topics").lean() ||
                 await PromptSet.findById(unitID).select("promptset_title main_topic secondary_topics").lean();

    if (!unit) {
        return { unitTitle: "Unknown Unit", unitType: "Unknown", main_topic: "Unknown", secondary_topics: [] };
    }

    return {
        unitTitle: unit.article_title || unit.video_title || unit.interview_title ||
                   unit.exercise_title || unit.template_title || unit.promptset_title || "Unknown Unit",
        unitType: unit.article_title ? "Article" :
                  unit.video_title ? "Video" :
                  unit.interview_title ? "Interview" :
                  unit.exercise_title ? "Exercise" :
                  unit.template_title ? "Template" :
                  unit.promptset_title ? "Prompt Set" : "Unknown",
        main_topic: unit.main_topic || "Unknown Topic",
        secondary_topics: unit.secondary_topics || []
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
const getMemberEngagementReport = async (req, res) => {
  try {
    console.log("✅ Fetching Member Engagement Report (per-member aggregation)…");

    // 1) Leader for header
    const leader = await Leader.findById(req.user.id).select("groupName").lean();
    if (!leader) {
      console.error("❌ Leader not found.");
      return res.status(403).json({ error: "Access denied", message: "Leader not found." });
    }

    // 2) Members of this leader’s group
    const members = await GroupMember.find({ groupId: req.user.id })
      .select("_id name")
      .lean();

    if (!members.length) {
      console.warn("⚠️ No group members found.");
      return res.render("report_views/memberengagement", {
        layout: "dashboardlayout",
        leaderGroupName: leader.groupName,
        memberEngagementReports: []
      });
    }

    const memberIds = members.map(m => m._id);
    const nameById = new Map(members.map(m => [m._id.toString(), m.name]));

    // 3) Pull data in bulk

    // 3a) Prompt set completions (for completed sets + badges + topics)
    const promptCompletions = await PromptSetCompletion
      .find({ memberId: { $in: memberIds } })
      .populate("promptSetId", "promptset_title main_topic secondary_topics")
      .lean();

    // Group completions by member
    const completionsByMember = new Map();
    for (const c of promptCompletions) {
      const key = c.memberId.toString();
      if (!completionsByMember.has(key)) completionsByMember.set(key, []);
      completionsByMember.get(key).push(c);
    }

    // 3b) Units completed (Notes) grouped per member
    const notes = await Notes.find({ memberID: { $in: memberIds } }).lean();
    const notesByMember = new Map();
    for (const n of notes) {
      const key = n.memberID.toString();
      if (!notesByMember.has(key)) notesByMember.set(key, []);
      notesByMember.get(key).push(n);
    }

    // 3c) Units contributed (authored by team members), grouped per author
    const [
      art, vid, intv, ex, tpl, psets
    ] = await Promise.all([
      Article.find({ "author.id": { $in: memberIds } }).select("article_title main_topic secondary_topics author.id").lean(),
      Video.find({ "author.id": { $in: memberIds } }).select("video_title main_topic secondary_topics author.id").lean(),
      Interview.find({ "author.id": { $in: memberIds } }).select("interview_title main_topic secondary_topics author.id").lean(),
      Exercise.find({ "author.id": { $in: memberIds } }).select("exercise_title main_topic secondary_topics author.id").lean(),
      Template.find({ "author.id": { $in: memberIds } }).select("template_title main_topic secondary_topics author.id").lean(),
      PromptSet.find({ "author.id": { $in: memberIds } }).select("promptset_title main_topic secondary_topics author.id").lean()
    ]);

    const pushGrp = (map, key, val) => {
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(val);
    };

    const contribByMember = new Map();

    for (const u of art)  pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.article_title, unitType: "Article",  main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });
    for (const u of vid)  pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.video_title,   unitType: "Video",    main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });
    for (const u of intv) pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.interview_title,unitType: "Interview",main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });
    for (const u of ex)   pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.exercise_title, unitType: "Exercise", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });
    for (const u of tpl)  pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.template_title, unitType: "Template", main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });
    for (const u of psets)pushGrp(contribByMember, u.author?.id?.toString?.() || "", { unitTitle: u.promptset_title,unitType: "Prompt Set",main_topic: u.main_topic, secondary_topics: u.secondary_topics || [] });

    // 4) Build rows per member in the shapes the view expects
    const memberEngagementReports = [];

    for (const m of members) {
      const mid = m._id.toString();

      // Prompt sets completed (title + date)
      const myComps = completionsByMember.get(mid) || [];
      const promptSetsCompleted = myComps.map(c => ({
        name: c.promptSetId?.promptset_title || "Unknown Prompt Set",
        dateCompleted: c.completedAt || c.createdAt
      }));

      // Badges earned
      const badgesEarned = myComps.flatMap(c => {
        const img = c.earnedBadge?.image;
        const nm  = c.earnedBadge?.name;
        return (img || nm)
          ? [{ badgeImage: img || "/images/default-badge.png", badgeName: nm || "a Twennie Badge" }]
          : [];
      });

      // Units completed (via Notes → resolve unit details)
      const myNotes = notesByMember.get(mid) || [];
      const unitsCompleted = [];
      const topicsFromCompleted = [];

      for (const n of myNotes) {
        const d = await resolveUnitDetails(n.unitID);
        unitsCompleted.push({ unitTitle: d.unitTitle, unitType: d.unitType });
        if (d.main_topic) topicsFromCompleted.push(d.main_topic);
        if (Array.isArray(d.secondary_topics)) topicsFromCompleted.push(...d.secondary_topics);
      }

      // Units contributed (already shaped)
      const myContrib = contribByMember.get(mid) || [];
      const unitsContributed = myContrib.map(u => ({ unitTitle: u.unitTitle, unitType: u.unitType }));

      // Topics engaged (from completions, completed units, contributions)
      const topicsFromComps = myComps.flatMap(c => {
        const main = c.promptSetId?.main_topic ? [c.promptSetId.main_topic] : [];
        const secs = Array.isArray(c.promptSetId?.secondary_topics) ? c.promptSetId.secondary_topics : [];
        return [...main, ...secs];
      });

      const topicsFromContrib = myContrib.flatMap(u => {
        const main = u.main_topic ? [u.main_topic] : [];
        const secs = Array.isArray(u.secondary_topics) ? u.secondary_topics : [];
        return [...main, ...secs];
      });

      const topicsEngaged = Array.from(
        new Set(
          [...topicsFromComps, ...topicsFromCompleted, ...topicsFromContrib].filter(Boolean)
        )
      ).sort((a, b) => a.localeCompare(b));

      // Optional sorting for nicer output
      promptSetsCompleted.sort((a, b) => (a.dateCompleted || 0) - (b.dateCompleted || 0));
      badgesEarned.sort((a, b) => (a.badgeName || "").localeCompare(b.badgeName || ""));
      unitsCompleted.sort((a, b) => a.unitTitle.localeCompare(b.unitTitle));
      unitsContributed.sort((a, b) => a.unitTitle.localeCompare(b.unitTitle));

      memberEngagementReports.push({
        memberName: nameById.get(mid) || "Unknown Member",
        promptSetsCompleted,
        badgesEarned,
        unitsCompleted,
        unitsContributed,
        topicsEngaged
      });
    }

    // 5) Render
    return res.render("report_views/memberengagement", {
      layout: "dashboardlayout",
      leaderGroupName: leader.groupName,
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
