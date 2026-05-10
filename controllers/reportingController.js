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
const Member = require('../models/member_models/member');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');




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
  secondary_topics: Array.isArray(doc?.secondary_topics)
    ? doc.secondary_topics
    : [],
  long_summary:
    doc?.long_summary ||
    doc?.full_summary ||
    doc?.summary ||
    ""
});

// Try each model in priority order
const article = await Article.findById(id)
  .select("article_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (article) {
  return normalize(article, article.article_title, "Article");
}

const video = await Video.findById(id)
  .select("video_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (video) {
  return normalize(video, video.video_title, "Video");
}

const interview = await Interview.findById(id)
  .select("interview_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (interview) {
  return normalize(interview, interview.interview_title, "Interview");
}

const exercise = await Exercise.findById(id)
  .select("exercise_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (exercise) {
  return normalize(exercise, exercise.exercise_title, "Exercise");
}

const template = await Template.findById(id)
  .select("template_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (template) {
  return normalize(template, template.template_title, "Template");
}

const promptSet = await PromptSet.findById(id)
  .select("promptset_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (promptSet) {
  return normalize(promptSet, promptSet.promptset_title, "Prompt Set");
}

// ✅ Missions
const mission = await Mission.findById(id)
  .select("mission_title main_topic secondary_topics long_summary full_summary summary")
  .lean();

if (mission) {
  return normalize(mission, mission.mission_title, "Mission");
}

// ✅ Nuggets
const nugget = await Nugget.findById(id)
  .select("title discipline client region long_summary full_summary summary")
  .lean();

if (nugget) {
  return {
    unitTitle: nugget.title || "Untitled Nugget",
    unitType: "Nugget",
    main_topic:
      nugget.discipline ||
      nugget.client ||
      nugget.region ||
      "Unknown Topic",
    secondary_topics: [],
    long_summary:
      nugget.long_summary ||
      nugget.full_summary ||
      nugget.summary ||
      ""
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

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const uniq = (arr) => Array.from(new Set(arr));
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    const leaderId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

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

    const leaderProfile = await LeaderProfile
      .findOne({ $or: [{ leaderId: leaderDoc._id }, { groupId: leaderDoc._id }] })
      .select("profileImage")
      .lean();

    const memberIdsFromLeader = safeArray(leaderDoc.members);

    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    const groupMemberProfiles = groupMembers.length
      ? await GroupMemberProfile.find({
          groupMemberId: { $in: groupMembers.map(m => m._id) }
        })
          .select("groupMemberId profileImage")
          .lean()
      : [];

    const profileImageByMemberId = new Map(
      groupMemberProfiles.map(profile => [
        toIdString(profile.groupMemberId),
        profile.profileImage || "/images/default-avatar.png"
      ])
    );

    const reportPeople = [
      {
        _id: leaderDoc._id,
        name: leaderName,
        memberImage: leaderProfile?.profileImage || "/images/default-avatar.png"
      },
      ...groupMembers.map(m => ({
        _id: m._id,
        name: m.name || "Group Member",
        memberImage: profileImageByMemberId.get(toIdString(m._id)) || "/images/default-avatar.png"
      }))
    ];

    const personIds = reportPeople.map(p => p._id);
    const nameById = new Map(reportPeople.map(p => [toIdString(p._id), p.name]));
    const imageById = new Map(reportPeople.map(p => [toIdString(p._id), p.memberImage]));

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

    const [promptCompletions, notes, missions] = await Promise.all([
      PromptSetCompletion.find({ memberId: { $in: personIds } })
        .populate("promptSetId", "promptset_title main_topic secondary_topics")
        .lean(),

      Notes.find({ memberID: { $in: personIds } }).lean(),

      Mission.find({})
        .select("_id mission_title main_topic secondary_topics")
        .lean()
    ]);

    const missionTitleById = new Map(
      safeArray(missions).map(m => [
        toIdString(m._id),
        m.mission_title || "Untitled mission"
      ])
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

    const completionsByPerson = new Map();

    for (const c of safeArray(promptCompletions)) {
      const key = toIdString(c.memberId);
      if (!key) continue;

      if (!completionsByPerson.has(key)) {
        completionsByPerson.set(key, []);
      }

      completionsByPerson.get(key).push(c);
    }

    const notesByPerson = new Map();

    for (const n of safeArray(notes)) {
      const key = toIdString(n.memberID);
      if (!key) continue;

      if (!notesByPerson.has(key)) {
        notesByPerson.set(key, []);
      }

      notesByPerson.get(key).push(n);
    }

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

    const memberEngagementReports = [];
    const groupedUnitsMap = new Map();

    for (const p of reportPeople) {
      const pid = toIdString(p._id);
      const personName = nameById.get(pid) || "Unknown";
      const memberImage = imageById.get(pid) || "/images/default-avatar.png";

      const myComps = completionsByPerson.get(pid) || [];

      const promptSetsCompleted = myComps
        .map(c => ({
          name: c.promptSetId?.promptset_title || "Unknown Prompt Set",
          dateCompleted: c.completedAt || c.createdAt || null
        }))
        .sort((a, b) => new Date(a.dateCompleted || 0) - new Date(b.dateCompleted || 0));

      const topicsFromComps = myComps.flatMap(c => {
        const main = c.promptSetId?.main_topic ? [c.promptSetId.main_topic] : [];
        const secs = Array.isArray(c.promptSetId?.secondary_topics)
          ? c.promptSetId.secondary_topics
          : [];

        return [...main, ...secs];
      });

      const myNotes = notesByPerson.get(pid) || [];

      const unitSeen = new Set();
      const missionSeen = new Set();

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

        if (unitTypeLower === "mission") {
          if (!missionSeen.has(unitIdStr)) {
            missionSeen.add(unitIdStr);

            missionsCompleted.push({
              missionId: unitIdStr,
              missionTitle: missionTitleById.get(unitIdStr) || unitTitle || "Untitled mission",
              dateCompleted: n.createdAt || n.updatedAt || null
            });
          }

          const mt = missionTopicsById.get(unitIdStr);

          if (mt?.main) topicsFromCompleted.push(mt.main);

          if (Array.isArray(mt?.secondary) && mt.secondary.length) {
            topicsFromCompleted.push(...mt.secondary);
          }

          if (!mt?.main && d.main_topic) {
            topicsFromCompleted.push(d.main_topic);
          }

          if (
            (!mt?.secondary || !mt.secondary.length) &&
            Array.isArray(d.secondary_topics) &&
            d.secondary_topics.length
          ) {
            topicsFromCompleted.push(...d.secondary_topics);
          }

          continue;
        }

        if (unitSeen.has(unitIdStr)) continue;

        unitSeen.add(unitIdStr);

        unitsCompleted.push({
          unitTitle,
          unitType
        });

        if (d.main_topic) {
          topicsFromCompleted.push(d.main_topic);
        }

        if (Array.isArray(d.secondary_topics) && d.secondary_topics.length) {
          topicsFromCompleted.push(...d.secondary_topics);
        }

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
        memberImage,
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

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");

    const leaderId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    const leaderDoc = await Leader.findById(leaderId)
      .select("_id name groupLeaderName groupName members")
      .lean();

    if (!leaderDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    const leaderName = leaderDoc.groupLeaderName || leaderDoc.name || "Leader";

    const leaderProfile = await LeaderProfile
      .findOne({ $or: [{ leaderId: leaderDoc._id }, { groupId: leaderDoc._id }] })
      .select("profileImage")
      .lean();

    const memberIdsFromLeader = safeArray(leaderDoc.members);

    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    const groupMemberProfiles = groupMembers.length
      ? await GroupMemberProfile.find({
          groupMemberId: { $in: groupMembers.map(m => m._id) }
        })
          .select("groupMemberId profileImage")
          .lean()
      : [];

    const profileImageByMemberId = new Map(
      groupMemberProfiles.map(profile => [
        toIdString(profile.groupMemberId),
        profile.profileImage || "/images/default-avatar.png"
      ])
    );

    const people = [
      {
        _id: leaderDoc._id,
        name: leaderName,
        role: "leader",
        memberImage: leaderProfile?.profileImage || "/images/default-avatar.png"
      },
      ...groupMembers.map(m => ({
        _id: m._id,
        name: m.name || "Group Member",
        role: "member",
        memberImage: profileImageByMemberId.get(toIdString(m._id)) || "/images/default-avatar.png"
      }))
    ];

    const nameById = new Map(people.map(p => [toIdString(p._id), p.name]));
    const roleById = new Map(people.map(p => [toIdString(p._id), p.role]));
    const imageById = new Map(people.map(p => [toIdString(p._id), p.memberImage]));

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

    const nuggetIds = [];

    for (const tag of nuggetTags) {
      const units = safeArray(tag.associatedUnits);

      for (const unit of units) {
        if (String(unit.unitType || "").toLowerCase() !== "nugget") continue;

        const nuggetId = unit.item?.toString?.();

        if (nuggetId) {
          nuggetIds.push(nuggetId);
        }
      }
    }

    const uniqueNuggetIds = Array.from(new Set(nuggetIds));

    const nuggets = uniqueNuggetIds.length
      ? await Nugget.find({ _id: { $in: uniqueNuggetIds } })
          .select("title discipline client region monitoringNotes")
          .lean()
      : [];

    const nuggetById = new Map(
      nuggets.map(nugget => [toIdString(nugget._id), nugget])
    );

    const rowByNuggetId = new Map();

    for (const tag of nuggetTags) {
      const assignmentName = tag.name || "Untitled Assignment";
      const assignedAt = tag.createdAt || null;

      const units = safeArray(tag.associatedUnits);
      const assignedTo = safeArray(tag.assignedTo);

      const monitors = [];
      const instructions = [];

      for (const assignment of assignedTo) {
        const memberId = toIdString(assignment.member);

        if (!memberId) continue;

        monitors.push({
          memberId,
          memberName: nameById.get(memberId) || "Unknown",
          memberImage: imageById.get(memberId) || "/images/default-avatar.png",
          role: roleById.get(memberId) || ""
        });

        if (assignment.instructions) {
          instructions.push(assignment.instructions);
        }
      }

      if (!monitors.length) {
        monitors.push({
          memberId: toIdString(leaderDoc._id),
          memberName: leaderName,
          memberImage: leaderProfile?.profileImage || "/images/default-avatar.png",
          role: "leader"
        });
      }

      const isAssigned = assignedTo.length > 0;

      for (const unit of units) {
        if (String(unit.unitType || "").toLowerCase() !== "nugget") continue;

        const nuggetId = unit.item?.toString?.();

        if (!nuggetId) continue;

        const nugget = nuggetById.get(nuggetId);

        const monitoringNotes = safeArray(nugget?.monitoringNotes)
          .map(note => {
            const addedById =
              note.addedBy ||
              note.memberID ||
              note.memberId ||
              note.createdBy ||
              null;

            const addedByIdString = toIdString(addedById);

            return {
              note: note.note || note.note_content || "",
              addedByNameSnapshot:
                note.addedByNameSnapshot ||
                (addedByIdString ? nameById.get(addedByIdString) : null) ||
                "Twennie member",
              addedByImage:
                (addedByIdString ? imageById.get(addedByIdString) : null) ||
                "/images/default-avatar.png",
              memberImage:
                (addedByIdString ? imageById.get(addedByIdString) : null) ||
                "/images/default-avatar.png",
              memberRole:
                addedByIdString ? roleById.get(addedByIdString) || "" : "",
              createdAt: note.createdAt || note.updatedAt || null
            };
          })
          .sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0));

        const baseRow = rowByNuggetId.get(nuggetId) || {
          nuggetId,
          nuggetTitle: nugget?.title || "Untitled Nugget",
          discipline: nugget?.discipline || "",
          client: nugget?.client || "",
          region: nugget?.region || "",

          assignmentName,
          assignmentDescription: "",
          assignedAt,

          isAssigned,
          monitoredBy: [],
          instructions: [],
          monitoringNotes
        };

        if (!baseRow.assignedAt || (assignedAt && new Date(assignedAt) < new Date(baseRow.assignedAt))) {
          baseRow.assignedAt = assignedAt;
        }

        if (!baseRow.assignmentName) {
          baseRow.assignmentName = assignmentName;
        }

        if (isAssigned) {
          baseRow.isAssigned = true;
        }

        const existingMonitorKeys = new Set(
          safeArray(baseRow.monitoredBy).map(m => `${m.memberId || ""}::${m.memberName}::${m.role || ""}`)
        );

        for (const monitor of monitors) {
          const key = `${monitor.memberId || ""}::${monitor.memberName}::${monitor.role || ""}`;

          if (!existingMonitorKeys.has(key)) {
            existingMonitorKeys.add(key);
            baseRow.monitoredBy.push(monitor);
          }
        }

        const instructionSet = new Set(baseRow.instructions || []);

        for (const instruction of instructions) {
          if (!instruction) continue;

          if (!instructionSet.has(instruction)) {
            instructionSet.add(instruction);
            baseRow.instructions.push(instruction);
          }
        }

        baseRow.monitoringNotes = monitoringNotes;

        rowByNuggetId.set(nuggetId, baseRow);
      }
    }

    const monitoredNuggets = Array.from(rowByNuggetId.values())
      .map(row => {
        row.monitoredBy = safeArray(row.monitoredBy).sort((a, b) =>
          (a.memberName || "").localeCompare(b.memberName || "")
        );

        row.instructions = safeArray(row.instructions).sort((a, b) =>
          (a || "").localeCompare(b || "")
        );

        row.monitoringNotes = safeArray(row.monitoringNotes);

        return row;
      })
      .sort((a, b) =>
        (a.nuggetTitle || "").localeCompare(b.nuggetTitle || "")
      );

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
// Option A view shape:
// - ONE record per prompt set
// - Prompts rendered ONCE as a header row
// - Member rows below with member-specific notes + completion date
const getPromptSetsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Prompt Sets Completed Report (split completed + notes; leader+members)…");

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    const leaderId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

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

    const leaderProfile = await LeaderProfile
      .findOne({ $or: [{ leaderId: leaderDoc._id }, { groupId: leaderDoc._id }] })
      .select("profileImage")
      .lean();

    const memberIdsFromLeader = safeArray(leaderDoc.members);

    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    const groupMemberProfiles = groupMembers.length
      ? await GroupMemberProfile.find({
          groupMemberId: { $in: groupMembers.map(m => m._id) }
        })
          .select("groupMemberId profileImage")
          .lean()
      : [];

    const profileImageByMemberId = new Map(
      groupMemberProfiles.map(profile => [
        toIdString(profile.groupMemberId),
        profile.profileImage || "/images/default-avatar.png"
      ])
    );

    const reportPeople = [
      {
        _id: leaderDoc._id,
        name: leaderName,
        memberImage: leaderProfile?.profileImage || "/images/default-avatar.png"
      },
      ...groupMembers.map(m => ({
        _id: m._id,
        name: m.name || "Group Member",
        memberImage: profileImageByMemberId.get(toIdString(m._id)) || "/images/default-avatar.png"
      }))
    ];

    const personIds = reportPeople.map(p => p._id);
    const nameById = new Map(reportPeople.map(p => [toIdString(p._id), p.name]));
    const imageById = new Map(reportPeople.map(p => [toIdString(p._id), p.memberImage]));

    if (!personIds.length) {
      return res.render("report_views/promptsetscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isPromptSetsCompleted: true,
        completedPromptSetsReports: [],
        promptNotesReports: []
      });
    }

    const [progresses, completions] = await Promise.all([
      PromptSetProgress.find({ memberId: { $in: personIds } })
        .populate("promptSetId")
        .lean(),

      PromptSetCompletion.find({ memberId: { $in: personIds } })
        .populate("promptSetId")
        .lean()
    ]);

    const TOTAL_PROMPTS = 21;

    const completedByPromptSet = new Map();

    for (const comp of safeArray(completions)) {
      const ps = comp.promptSetId;
      const psId = toIdString(ps?._id);
      const memberId = toIdString(comp.memberId);

      if (!ps || !psId || !memberId) continue;

      if (!completedByPromptSet.has(psId)) {
        completedByPromptSet.set(psId, {
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          completedBy: []
        });
      }

      completedByPromptSet.get(psId).completedBy.push({
        memberId,
        memberName: nameById.get(memberId) || "Unknown Member",
        memberImage: imageById.get(memberId) || "/images/default-avatar.png",
        dateCompleted: comp.completedAt || comp.createdAt || comp.updatedAt || null
      });
    }

    const completedPromptSetsReports = Array.from(completedByPromptSet.values())
      .map(row => {
        const deduped = new Map();

        for (const entry of safeArray(row.completedBy)) {
          const key = `${entry.memberId}::${entry.dateCompleted ? new Date(entry.dateCompleted).getTime() : 0}`;
          if (!deduped.has(key)) deduped.set(key, entry);
        }

        row.completedBy = Array.from(deduped.values()).sort((a, b) => {
          const ad = a.dateCompleted ? new Date(a.dateCompleted) : new Date(0);
          const bd = b.dateCompleted ? new Date(b.dateCompleted) : new Date(0);
          if (ad.getTime() !== bd.getTime()) return ad - bd;
          return sortAZ(a.memberName, b.memberName);
        });

        return row;
      })
      .sort((a, b) => sortAZ(a.promptSetTitle, b.promptSetTitle));

    const notesByPromptSet = new Map();

    for (const prog of safeArray(progresses)) {
      const ps = prog.promptSetId;
      const psId = toIdString(ps?._id);
      const memberId = toIdString(prog.memberId);

      if (!ps || !psId || !memberId) continue;

      if (!notesByPromptSet.has(psId)) {
        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const headlineKey = `prompt_headline${idx}`;
          const textKey = `Prompt${idx}`;

          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${idx}`,
            promptText: ps?.[textKey] || ""
          };
        });

        notesByPromptSet.set(psId, {
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          prompts,
          completedBy: []
        });
      }

      const notesArr = safeArray(prog.notes);

      const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
        const noteIndex = idx === 0 ? -1 : idx - 1;
        const content = noteIndex >= 0 ? safeString(notesArr[noteIndex]).trim() : "";

        return {
          notes: content
            ? [{
                content,
                dateSubmitted: prog.updatedAt || prog.createdAt || null
              }]
            : []
        };
      });

      notesByPromptSet.get(psId).completedBy.push({
        memberId,
        memberName: nameById.get(memberId) || "Unknown Member",
        memberImage: imageById.get(memberId) || "/images/default-avatar.png",
        dateCompleted: null,
        promptNotes
      });
    }

    const promptNotesReports = Array.from(notesByPromptSet.values())
      .map(row => {
        const byMember = new Map();

        for (const entry of safeArray(row.completedBy)) {
          const key = entry.memberId || entry.memberName;
          if (!byMember.has(key)) byMember.set(key, entry);
        }

        row.completedBy = Array.from(byMember.values()).sort((a, b) =>
          sortAZ(a.memberName, b.memberName)
        );

        return row;
      })
      .sort((a, b) => sortAZ(a.promptSetTitle, b.promptSetTitle));

    return res.render("report_views/promptsetscompleted", {
      layout: "dashboardlayout",
      leaderGroupName: leaderDoc.groupName,
      isPromptSetsCompleted: true,
      completedPromptSetsReports,
      promptNotesReports
    });

  } catch (err) {
    console.error("❌ Error loading Prompt Sets Completed Report:", err);
    return res.status(500).send("Server error");
  }
};






// ✅ Fetch Units Completed Report (grouped by unit, includes notes)
// UPDATED to:
// - use leader.members as source of truth (like Member Engagement)
// - include leader as a “person” (optional; harmless if leader has no Notes)
const getUnitsCompletedReport = async (req, res) => {
  try {
    console.log("✅ Fetching Units Completed Report (grouped by unit; leader+members)…");

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");

    const leaderId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!leaderId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your leader account."
      });
    }

    const leaderDoc = await Leader.findById(leaderId)
      .select("_id name groupLeaderName groupName members")
      .lean();

    if (!leaderDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Leader account not found."
      });
    }

    const leaderName = leaderDoc.groupLeaderName || leaderDoc.name || "Leader";

    const leaderProfile = await LeaderProfile
      .findOne({ $or: [{ leaderId: leaderDoc._id }, { groupId: leaderDoc._id }] })
      .select("profileImage")
      .lean();

    const memberIdsFromLeader = safeArray(leaderDoc.members);

    const groupMembers = memberIdsFromLeader.length
      ? await GroupMember.find({ _id: { $in: memberIdsFromLeader } })
          .select("_id name")
          .lean()
      : [];

    const groupMemberProfiles = groupMembers.length
      ? await GroupMemberProfile.find({
          groupMemberId: { $in: groupMembers.map(m => m._id) }
        })
          .select("groupMemberId profileImage")
          .lean()
      : [];

    const profileImageByMemberId = new Map(
      groupMemberProfiles.map(profile => [
        toIdString(profile.groupMemberId),
        profile.profileImage || "/images/default-avatar.png"
      ])
    );

    const reportPeople = [
      {
        _id: leaderDoc._id,
        name: leaderName,
        memberImage: leaderProfile?.profileImage || "/images/default-avatar.png"
      },
      ...groupMembers.map(m => ({
        _id: m._id,
        name: m.name || "Group Member",
        memberImage: profileImageByMemberId.get(toIdString(m._id)) || "/images/default-avatar.png"
      }))
    ];

    const personIds = reportPeople.map(p => p._id);

    const nameById = new Map(
      reportPeople.map(p => [toIdString(p._id), p.name])
    );

    const imageById = new Map(
      reportPeople.map(p => [toIdString(p._id), p.memberImage])
    );

    if (!personIds.length) {
      return res.render("report_views/unitscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isUnitsCompleted: true,
        unitsCompletedReports: []
      });
    }

    const notes = await Notes.find({ memberID: { $in: personIds } }).lean();

    const filteredNotes = safeArray(notes).filter(n => {
      return String(n.unitType || "").toLowerCase() !== "mission";
    });

    if (!filteredNotes.length) {
      return res.render("report_views/unitscompleted", {
        layout: "dashboardlayout",
        leaderGroupName: leaderDoc.groupName,
        isUnitsCompleted: true,
        unitsCompletedReports: []
      });
    }

    const byUnit = new Map();

    for (const n of filteredNotes) {
      const unitId = toIdString(n.unitID);
      if (!unitId) continue;

      if (!byUnit.has(unitId)) {
        const details = await resolveUnitDetails(unitId);

        if (String(details.unitType || "").toLowerCase() === "mission") continue;

        byUnit.set(unitId, {
          unitTitle: details.unitTitle,
          unitType: details.unitType,
          main_topic: details.main_topic,
          secondary_topics: details.secondary_topics || [],
          long_summary: details.long_summary || details.full_summary || details.summary || "",
          memberNotesMap: new Map()
        });
      }

      const unitEntry = byUnit.get(unitId);

      const memberId = toIdString(n.memberID);
      if (!memberId) continue;

      if (!unitEntry.memberNotesMap.has(memberId)) {
        unitEntry.memberNotesMap.set(memberId, {
          memberId,
          memberName: nameById.get(memberId) || "Unknown Member",
          memberImage: imageById.get(memberId) || "/images/default-avatar.png",
          notes: []
        });
      }

      unitEntry.memberNotesMap.get(memberId).notes.push({
        content: n.note_content || "",
        dateSubmitted: n.createdAt || n.updatedAt || null
      });
    }

    const unitsCompletedReports = Array.from(byUnit.values()).map(unit => {
      const memberNotes = Array.from(unit.memberNotesMap.values()).map(m => {
        m.notes.sort((a, b) => {
          return new Date(a.dateSubmitted || 0) - new Date(b.dateSubmitted || 0);
        });

        return m;
      });

      return {
        unitTitle: unit.unitTitle,
        unitType: unit.unitType,
        main_topic: unit.main_topic,
        secondary_topics: unit.secondary_topics,
        long_summary: unit.long_summary || "",

        completedBy: memberNotes.map(m => ({
          memberId: m.memberId,
          memberName: m.memberName,
          memberImage: m.memberImage || "/images/default-avatar.png",
          dateCompleted: m.notes[0]?.dateSubmitted || null
        })),

        memberNotes
      };
    });

    unitsCompletedReports.sort((a, b) =>
      (a.unitTitle || "").localeCompare(b.unitTitle || "")
    );

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



// ✅ Fetch Group Member's Own Completed Prompt Sets Report
// Shape matches views/report_views/mycompletedpromptsets.hbs
const getMyCompletedPromptSetsReport = async (req, res) => {
  try {
    console.log("✅ Fetching Group Member Completed Prompt Sets Report…");
    console.log("req.user:", req.user);
console.log("req.session.user:", req.session?.user);

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    const memberId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!memberId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your member account."
      });
    }

    const memberDoc = await GroupMember.findById(memberId)
      .select("_id name")
      .lean();

      console.log("memberId from session/user:", memberId);
console.log("memberDoc found:", memberDoc);

    if (!memberDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Group member account not found."
      });
    }

    const [progresses, completions] = await Promise.all([
      PromptSetProgress.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean(),

      PromptSetCompletion.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean()
    ]);

    console.log("progresses found:", progresses.length);
console.log("completions found:", completions.length);
console.log("progress promptSetIds:", progresses.map(p => ({
  memberId: p.memberId?.toString?.(),
  promptSetId: p.promptSetId?._id?.toString?.() || p.promptSetId?.toString?.()
})));
console.log("completion promptSetIds:", completions.map(c => ({
  memberId: c.memberId?.toString?.(),
  promptSetId: c.promptSetId?._id?.toString?.() || c.promptSetId?.toString?.(),
  completedAt: c.completedAt
})));

    const TOTAL_PROMPTS = 21;

    const completionKey = (memberId, promptSetId) => `${memberId}::${promptSetId}`;
    const completionByKey = new Map(
      safeArray(completions).map(c => [
        completionKey(
          toIdString(c.memberId),
          toIdString(c.promptSetId?._id || c.promptSetId)
        ),
        c
      ])
    );

    // =========================================================
    // TABLE 1 DATA: COMPLETED PROMPT SETS ONLY
    // =========================================================
    const completedPromptSetsReports = safeArray(completions)
      .filter(comp => comp.promptSetId)
      .map(comp => {
        const ps = comp.promptSetId;

        return {
          promptSetId: toIdString(ps._id),
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          characteristics: safeArray(ps.characteristics),
          targetAudience: ps.targetAudience || "",
          dateCompleted: comp.completedAt || comp.createdAt || comp.updatedAt || null
        };
      })
      .sort((a, b) => {
        const ad = a.dateCompleted ? new Date(a.dateCompleted) : new Date(0);
        const bd = b.dateCompleted ? new Date(b.dateCompleted) : new Date(0);
        if (ad.getTime() !== bd.getTime()) return bd - ad;
        return sortAZ(a.promptSetTitle, b.promptSetTitle);
      });

    // =========================================================
    // TABLE 2 DATA: PROMPT NOTES / HISTORY
    // =========================================================
    const promptNotesReports = safeArray(progresses)
      .filter(prog => prog.promptSetId)
      .map(prog => {
        const ps = prog.promptSetId;
        const psId = toIdString(ps._id);

        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const headlineKey = `prompt_headline${idx}`;
          const textKey = `Prompt${idx}`;

          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${idx}`,
            promptText: ps?.[textKey] || ""
          };
        });

        const notesArr = safeArray(prog.notes);

        const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const noteIndex = idx === 0 ? -1 : idx - 1;
          const content = noteIndex >= 0 ? safeString(notesArr[noteIndex]).trim() : '';

          return {
            notes: content
              ? [{
                  content,
                  dateSubmitted: prog.updatedAt || prog.createdAt || null
                }]
              : []
          };
        });

        const matchingCompletion = completionByKey.get(
          completionKey(toIdString(prog.memberId), psId)
        );

        return {
          promptSetId: psId,
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          characteristics: safeArray(ps.characteristics),
          targetAudience: ps.targetAudience || "",
          dateCompleted: matchingCompletion
            ? (matchingCompletion.completedAt || matchingCompletion.createdAt || matchingCompletion.updatedAt || null)
            : null,
          prompts,
          promptNotes
        };
      })
      .sort((a, b) => sortAZ(a.promptSetTitle, b.promptSetTitle));
console.log("completedPromptSetsReports length:", completedPromptSetsReports.length);
console.log("promptNotesReports length:", promptNotesReports.length);
    return res.render("report_views/mycompletedpromptsets", {
      layout: "dashboardlayout",
      isMyCompletedPromptSets: true,
      completedPromptSetsReports,
      promptNotesReports
    });
  } catch (err) {
    console.error("❌ Error loading Group Member Completed Prompt Sets Report:", err);
    return res.status(500).send("Server error");
  }
};



// ✅ Fetch Group Member's Learning Notes Report
// Includes notes on standard learning units only:
// Article, Video, Interview, Exercise, Template
// Excludes Prompt Sets (separate report), Missions, Nuggets, Upcoming
// ✅ Fetch Group Member's Learning Notes Report
// Includes:
// - standard learning unit notes
// - prompt set notes history
const getMyLearningNotesReport = async (req, res) => {
  try {
    console.log("✅ Fetching My Learning Notes Report…");

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    const memberId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!memberId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your member account."
      });
    }

    const memberDoc = await GroupMember.findById(memberId)
      .select("_id name")
      .lean();

    if (!memberDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Group member account not found."
      });
    }

    const [notes, progresses, completions] = await Promise.all([
      Notes.find({ memberID: memberDoc._id })
        .sort({ createdAt: 1 })
        .lean(),

      PromptSetProgress.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean(),

      PromptSetCompletion.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean()
    ]);

    const uniqueUnitIds = Array.from(
      new Set(
        safeArray(notes)
          .map(n => toIdString(n.unitID))
          .filter(Boolean)
      )
    );

    const detailsByUnitId = new Map();

    await Promise.all(
      uniqueUnitIds.map(async (unitId) => {
        try {
          const details = await resolveUnitDetails(unitId);
          detailsByUnitId.set(unitId, details || {});
        } catch (err) {
          console.warn("⚠️ Could not resolve unit details for:", unitId, err?.message);
          detailsByUnitId.set(unitId, {});
        }
      })
    );

    const allowedUnitTypes = new Set([
      "article",
      "video",
      "interview",
      "exercise",
      "template"
    ]);

    const byUnit = new Map();

    for (const note of safeArray(notes)) {
      const unitId = toIdString(note.unitID);
      if (!unitId) continue;

      const details = detailsByUnitId.get(unitId) || {};
      const unitType = safeString(details.unitType).trim();
      const unitTypeLower = unitType.toLowerCase();

      if (!allowedUnitTypes.has(unitTypeLower)) continue;

      if (!byUnit.has(unitId)) {
        byUnit.set(unitId, {
          unitId,
          unitTitle: details.unitTitle || "Unknown Unit",
          unitType: unitType || "Unknown",
          main_topic: details.main_topic || "",
          secondary_topics: safeArray(details.secondary_topics),
          notes: []
        });
      }

      byUnit.get(unitId).notes.push({
        content: note.note_content || "",
        dateSubmitted: note.createdAt || note.updatedAt || null
      });
    }

    const myLearningNotesReports = Array.from(byUnit.values())
      .map(unit => {
        unit.notes = safeArray(unit.notes).sort((a, b) => {
          const ad = a.dateSubmitted ? new Date(a.dateSubmitted) : new Date(0);
          const bd = b.dateSubmitted ? new Date(b.dateSubmitted) : new Date(0);
          return ad - bd;
        });

        unit.latestNoteDate =
          unit.notes.length > 0
            ? unit.notes[unit.notes.length - 1].dateSubmitted
            : null;

        return unit;
      })
      .sort((a, b) => {
        const ad = a.latestNoteDate ? new Date(a.latestNoteDate) : new Date(0);
        const bd = b.latestNoteDate ? new Date(b.latestNoteDate) : new Date(0);
        return bd - ad;
      });

    // =========================================================
    // TABLE 2 DATA: PROMPT NOTES / HISTORY
    // =========================================================
    const TOTAL_PROMPTS = 21;

    const completionKey = (memberId, promptSetId) => `${memberId}::${promptSetId}`;
    const completionByKey = new Map(
      safeArray(completions).map(c => [
        completionKey(
          toIdString(c.memberId),
          toIdString(c.promptSetId?._id || c.promptSetId)
        ),
        c
      ])
    );

    const promptNotesReports = safeArray(progresses)
      .filter(prog => prog.promptSetId)
      .map(prog => {
        const ps = prog.promptSetId;
        const psId = toIdString(ps._id);

        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const headlineKey = `prompt_headline${idx}`;
          const textKey = `Prompt${idx}`;

          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${idx}`,
            promptText: ps?.[textKey] || ""
          };
        });

        const notesArr = safeArray(prog.notes);

        const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const noteIndex = idx === 0 ? -1 : idx - 1;
          const content = noteIndex >= 0 ? safeString(notesArr[noteIndex]).trim() : "";

          return {
            notes: content
              ? [{
                  content,
                  dateSubmitted: prog.updatedAt || prog.createdAt || null
                }]
              : []
          };
        });

        const matchingCompletion = completionByKey.get(
          completionKey(toIdString(prog.memberId), psId)
        );

        return {
          promptSetId: psId,
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          dateCompleted: matchingCompletion
            ? (matchingCompletion.completedAt || matchingCompletion.createdAt || matchingCompletion.updatedAt || null)
            : null,
          prompts,
          promptNotes
        };
      })
      .sort((a, b) => sortAZ(a.promptSetTitle, b.promptSetTitle));

    return res.render("report_views/mylearningnotes", {
      layout: "dashboardlayout",
      isMyLearningNotes: true,
      myLearningNotesReports,
      promptNotesReports
    });
  } catch (err) {
    console.error("❌ Error loading My Learning Notes Report:", err);
    return res.status(500).send("Server error");
  }
};

// ✅ Fetch Individual Member's Own Completed Prompt Sets Report
// Shape matches views/report_views/mycompletedpromptsets_individual.hbs
const getMyCompletedPromptSetsReportIndividual = async (req, res) => {
  try {
    console.log("✅ Fetching Individual Member Completed Prompt Sets Report…");

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");
    const sortAZ = (a, b) => safeString(a).localeCompare(safeString(b));

    const memberId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!memberId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your member account."
      });
    }

    const memberDoc = await Member.findById(memberId)
      .select("_id name")
      .lean();

    if (!memberDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Individual member account not found."
      });
    }

    const [progresses, completions] = await Promise.all([
      PromptSetProgress.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean(),

      PromptSetCompletion.find({ memberId: memberDoc._id })
        .populate("promptSetId")
        .lean()
    ]);

    const TOTAL_PROMPTS = 21;

    const completionKey = (memberId, promptSetId) => `${memberId}::${promptSetId}`;
    const completionByKey = new Map(
      safeArray(completions).map(c => [
        completionKey(
          toIdString(c.memberId),
          toIdString(c.promptSetId?._id || c.promptSetId)
        ),
        c
      ])
    );

    // =========================================================
    // TABLE 1 DATA: COMPLETED PROMPT SETS ONLY
    // =========================================================
    const completedPromptSetsReports = safeArray(completions)
      .filter(comp => comp.promptSetId)
      .map(comp => {
        const ps = comp.promptSetId;

        return {
          promptSetId: toIdString(ps._id),
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          characteristics: safeArray(ps.characteristics),
          targetAudience: ps.targetAudience || "",
          dateCompleted: comp.completedAt || comp.createdAt || comp.updatedAt || null
        };
      })
      .sort((a, b) => {
        const ad = a.dateCompleted ? new Date(a.dateCompleted) : new Date(0);
        const bd = b.dateCompleted ? new Date(b.dateCompleted) : new Date(0);
        if (ad.getTime() !== bd.getTime()) return bd - ad;
        return sortAZ(a.promptSetTitle, b.promptSetTitle);
      });

    // =========================================================
    // TABLE 2 DATA: PROMPT NOTES / HISTORY
    // =========================================================
    const promptNotesReports = safeArray(progresses)
      .filter(prog => prog.promptSetId)
      .map(prog => {
        const ps = prog.promptSetId;
        const psId = toIdString(ps._id);

        const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const headlineKey = `prompt_headline${idx}`;
          const textKey = `Prompt${idx}`;

          return {
            promptHeadline: ps?.[headlineKey] || `Prompt ${idx}`,
            promptText: ps?.[textKey] || ""
          };
        });

        const notesArr = safeArray(prog.notes);

        const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
          const noteIndex = idx === 0 ? -1 : idx - 1;
          const content = noteIndex >= 0 ? safeString(notesArr[noteIndex]).trim() : '';

          return {
            notes: content
              ? [{
                  content,
                  dateSubmitted: prog.updatedAt || prog.createdAt || null
                }]
              : []
          };
        });

        const matchingCompletion = completionByKey.get(
          completionKey(toIdString(prog.memberId), psId)
        );

        return {
          promptSetId: psId,
          promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
          main_topic: ps.main_topic || "",
          secondary_topics: safeArray(ps.secondary_topics),
          purpose: ps.purpose || "",
          characteristics: safeArray(ps.characteristics),
          targetAudience: ps.targetAudience || "",
          dateCompleted: matchingCompletion
            ? (matchingCompletion.completedAt || matchingCompletion.createdAt || matchingCompletion.updatedAt || null)
            : null,
          prompts,
          promptNotes
        };
      })
      .sort((a, b) => sortAZ(a.promptSetTitle, b.promptSetTitle));

    return res.render("report_views/mycompletedpromptsets_individual", {
      layout: "dashboardlayout",
      isMyCompletedPromptSetsIndividual: true,
      completedPromptSetsReports,
      promptNotesReports
    });
  } catch (err) {
    console.error("❌ Error loading Individual Member Completed Prompt Sets Report:", err);
    return res.status(500).send("Server error");
  }
};

// ✅ Fetch Individual Member's Learning Notes Report
// Includes notes on standard learning units only:
// Article, Video, Interview, Exercise, Template
// Excludes Prompt Sets (separate report), Missions, Nuggets, Upcoming
const getMyLearningNotesReportIndividual = async (req, res) => {
  try {
    console.log("✅ Fetching Individual Member Learning Notes Report…");

    const safeArray = (v) => (Array.isArray(v) ? v : []);
    const safeString = (v) => (v == null ? "" : String(v));
    const toIdString = (v) => (v && typeof v.toString === "function" ? v.toString() : "");

    const memberId = toIdString(req.user?._id || req.user?.id || req.session?.user?.id);

    if (!memberId) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Could not determine your member account."
      });
    }

    const memberDoc = await Member.findById(memberId)
      .select("_id name")
      .lean();

    if (!memberDoc) {
      return res.status(403).render("member_form_views/error", {
        layout: "memberformlayout",
        title: "Access denied",
        errorMessage: "Individual member account not found."
      });
    }

const [notes, progresses, completions] = await Promise.all([
  Notes.find({ memberID: memberDoc._id })
    .sort({ createdAt: 1 })
    .lean(),

  PromptSetProgress.find({ memberId: memberDoc._id })
    .populate("promptSetId")
    .lean(),

  PromptSetCompletion.find({ memberId: memberDoc._id })
    .populate("promptSetId")
    .lean()
]);

    if (!notes.length) {
      return res.render("report_views/mylearningnotes_individual", {
        layout: "dashboardlayout",
        isMyLearningNotesIndividual: true,
        myLearningNotesReports: []
      });
    }

    const uniqueUnitIds = Array.from(
      new Set(
        safeArray(notes)
          .map(n => toIdString(n.unitID))
          .filter(Boolean)
      )
    );

    const detailsByUnitId = new Map();

    await Promise.all(
      uniqueUnitIds.map(async (unitId) => {
        try {
          const details = await resolveUnitDetails(unitId);
          detailsByUnitId.set(unitId, details || {});
        } catch (err) {
          console.warn("⚠️ Could not resolve unit details for individual member note:", unitId, err?.message);
          detailsByUnitId.set(unitId, {});
        }
      })
    );

    const allowedUnitTypes = new Set([
      "article",
      "video",
      "interview",
      "exercise",
      "template"
    ]);

    const byUnit = new Map();

    for (const note of notes) {
      const unitId = toIdString(note.unitID);
      if (!unitId) continue;

      const details = detailsByUnitId.get(unitId) || {};
      const unitType = safeString(details.unitType).trim();
      const unitTypeLower = unitType.toLowerCase();

      if (!allowedUnitTypes.has(unitTypeLower)) continue;

      if (!byUnit.has(unitId)) {
        byUnit.set(unitId, {
          unitId,
          unitTitle: details.unitTitle || "Unknown Unit",
          unitType: unitType || "Unknown",
          main_topic: details.main_topic || "",
          secondary_topics: safeArray(details.secondary_topics),
          notes: []
        });
      }

      byUnit.get(unitId).notes.push({
        content: note.note_content || "",
        dateSubmitted: note.createdAt || note.updatedAt || null
      });
    }

    const myLearningNotesReports = Array.from(byUnit.values())
      .map(unit => {
        unit.notes = safeArray(unit.notes).sort((a, b) => {
          const ad = a.dateSubmitted ? new Date(a.dateSubmitted) : new Date(0);
          const bd = b.dateSubmitted ? new Date(b.dateSubmitted) : new Date(0);
          return ad - bd;
        });

        unit.latestNoteDate =
          unit.notes.length > 0
            ? unit.notes[unit.notes.length - 1].dateSubmitted
            : null;

        return unit;
      })
      .sort((a, b) => {
        const ad = a.latestNoteDate ? new Date(a.latestNoteDate) : new Date(0);
        const bd = b.latestNoteDate ? new Date(b.latestNoteDate) : new Date(0);
        return bd - ad;
      });

      // =========================================================
// TABLE 2 DATA: PROMPT NOTES / HISTORY
// =========================================================
const TOTAL_PROMPTS = 21;

const completionKey = (memberId, promptSetId) => `${memberId}::${promptSetId}`;
const completionByKey = new Map(
  (completions || []).map(c => [
    completionKey(
      String(c.memberId),
      String(c.promptSetId?._id || c.promptSetId)
    ),
    c
  ])
);

const promptNotesReports = (progresses || [])
  .filter(prog => prog.promptSetId)
  .map(prog => {
    const ps = prog.promptSetId;
    const psId = String(ps._id);

    const prompts = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
      return {
        promptHeadline: ps?.[`prompt_headline${idx}`] || `Prompt ${idx}`,
        promptText: ps?.[`Prompt${idx}`] || ""
      };
    });

    const notesArr = prog.notes || [];

    const promptNotes = Array.from({ length: TOTAL_PROMPTS }, (_, idx) => {
      const noteIndex = idx === 0 ? -1 : idx - 1;
      const content = noteIndex >= 0 ? String(notesArr[noteIndex] || '').trim() : '';

      return {
        notes: content
          ? [{
              content,
              dateSubmitted: prog.updatedAt || prog.createdAt || null
            }]
          : []
      };
    });

    const matchingCompletion = completionByKey.get(
      completionKey(String(prog.memberId), psId)
    );

    return {
      promptSetId: psId,
      promptSetTitle: ps.promptset_title || "Unknown Prompt Set",
      main_topic: ps.main_topic || "",
      secondary_topics: ps.secondary_topics || [],
      purpose: ps.purpose || "",
      dateCompleted: matchingCompletion
        ? (matchingCompletion.completedAt || matchingCompletion.createdAt || matchingCompletion.updatedAt || null)
        : null,
      prompts,
      promptNotes
    };
  });

return res.render("report_views/mylearningnotes_individual", {
  layout: "dashboardlayout",
  isMyLearningNotesIndividual: true,
  myLearningNotesReports,
  promptNotesReports
});
  } catch (err) {
    console.error("❌ Error loading Individual Member Learning Notes Report:", err);
    return res.status(500).send("Server error");
  }
};





module.exports = {
  getMemberEngagementReport,
  getNuggetsMonitoredReport,
  getPromptSetsCompletedReport,
  getUnitsCompletedReport,
  getMyCompletedPromptSetsReport,
  getMyLearningNotesReport,
  getMyCompletedPromptSetsReportIndividual,
  getMyLearningNotesReportIndividual
};