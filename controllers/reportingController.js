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
const getMemberEngagementReport = async (req, res) => {
    try {
        console.log("✅ Fetching Member Engagement Report...");

        const leader = await Leader.findById(req.user.id).select("groupName").lean();
        if (!leader) {
            console.error("❌ Leader not found.");
            return res.status(403).json({ error: "Access denied", message: "Leader not found." });
        }

        const members = await GroupMember.find({ groupId: req.user.id }).select("_id name").lean();
        if (!members.length) {
            console.warn("⚠️ No group members found.");
        }

        const promptCompletions = await PromptSetCompletion.find({
            memberId: { $in: members.map(m => m._id) }
        }).populate("promptSetId", "promptset_title main_topic secondary_topics").lean();

        const notes = await Notes.find({ memberID: { $in: members.map(m => m._id) } }).lean();

        const reportData = await Promise.all(members.map(async (member) => {
            const memberPromptSets = promptCompletions.filter(p => p.memberId.toString() === member._id.toString());
            const memberNotes = notes.filter(n => n.memberID.toString() === member._id.toString());

            // ✅ Fetch completed units and extract topics
            const unitsCompleted = await Promise.all(memberNotes.map(async (n) => {
                return await resolveUnitDetails(n.unitID);
            }));

            // ✅ Fetch contributed units and extract topics
            const contributedUnits = await fetchContributedUnits(member._id);

            return {
                memberName: member.name,
                promptSetsCompleted: memberPromptSets.map(p => ({
                    name: p.promptSetId?.promptset_title || "Unknown Prompt Set",
                    dateCompleted: p.completedAt
                })),
                badgesEarned: memberPromptSets.flatMap(p =>
                    p.earnedBadge ? [{ badgeImage: p.earnedBadge.image, badgeName: p.earnedBadge.name }] : []
                ),
                unitsCompleted,
                unitsContributed: contributedUnits,
                topicsEngaged: [
                    ...memberPromptSets.flatMap(p => [p.promptSetId?.main_topic, ...(p.promptSetId?.secondary_topics || [])]),
                    ...unitsCompleted.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])]),
                    ...contributedUnits.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])])
                ]
            };
        }));

        res.render("report_views/memberengagement", {
            layout: "dashboardlayout",
            leaderGroupName: leader.groupName,
            memberEngagementReports: reportData
        });

    } catch (err) {
        console.error("❌ Error loading Member Engagement Report:", err);
        res.status(500).send("Server error");
    }
};

// ✅ Fetch Prompt Sets Completed Report
const getPromptSetsCompletedReport = async (req, res) => {
    try {
        console.log("✅ Fetching Prompt Sets Completed Report...");

        const leader = await Leader.findById(req.user.id).select("groupName").lean();
        if (!leader) {
            console.error("❌ Leader not found.");
            return res.status(403).json({ error: "Access denied", message: "Leader not found." });
        }

        const members = await GroupMember.find({ groupId: req.user.id }).select("_id").lean();
        if (!members.length) {
            console.warn("⚠️ No group members found.");
        }

        const promptSetCompletions = await PromptSetCompletion.find({
            memberId: { $in: members.map(m => m._id) }
        }).populate("promptSetId").lean();

        const reportData = await Promise.all(promptSetCompletions.map(async (completion) => {
            const promptSet = completion.promptSetId;
            if (!promptSet) return null;

            // ✅ Fetch the member name separately using Promise.all()
            const member = await GroupMember.findById(completion.memberId).select("name").lean() ||
                           await Leader.findById(completion.memberId).select("groupLeaderName").lean();
            const memberName = member?.name || member?.groupLeaderName || "Unknown Member";

            // ✅ Extract prompts 1-20 from the prompt set
            const prompts = Array.from({ length: 20 }, (_, index) => ({
                promptNumber: `Prompt ${index + 1}`,
                promptHeadline: promptSet[`prompt_headline${index + 1}`] || "No headline",
                promptText: promptSet[`Prompt${index + 1}`] || "No prompt text available"
            }));

            return {
                promptSetTitle: promptSet.promptset_title,
                main_topic: promptSet.main_topic,
                secondary_topics: promptSet.secondary_topics || [],
                purpose: promptSet.purpose || "No purpose provided",
                characteristics: promptSet.characteristics || [],
                targetAudience: promptSet.target_audience || "No audience specified",
                completedBy: [{
                    memberName,
                    dateCompleted: completion.completedAt
                }],
                prompts, // ✅ Row 1: Prompts 1-20
                promptNotes: await Promise.all(completion.notes.map(async (note, index) => ({
                    promptNumber: `Prompt ${index + 1}`,
                    notes: [{
                        memberName,
                        content: note
                    }]
                }))) // ✅ Row 2: Notes for each prompt
            };
        }));

        res.render("report_views/promptsetscompleted", {
            layout: "dashboardlayout",
            leaderGroupName: leader.groupName,
            promptSetsCompletedReports: reportData.filter(report => report !== null)
        });

    } catch (err) {
        console.error("❌ Error loading Prompt Sets Completed Report:", err);
        res.status(500).send("Server error");
    }
};








const getTeamEngagementReport = async (req, res) => {
    try {
        console.log("✅ Fetching Team Engagement Report...");

        // ✅ Fetch leader info
        const leader = await Leader.findById(req.user.id).select("groupName").lean();
        if (!leader) {
            console.error("❌ Leader not found for user ID:", req.user.id);
            return res.status(403).json({ error: "Access denied", message: "Leader not found." });
        }

        console.log("✅ Leader Found:", leader.groupName);

        // ✅ Fetch all group members under the leader
        const members = await GroupMember.find({ groupId: req.user.id }).select("_id").lean();
        if (!members.length) {
            console.warn("⚠️ No group members found for this leader.");
        }

        const memberIds = members.map(m => m._id);

        // ✅ Fetch all prompt set completions for the team
        const promptCompletions = await PromptSetCompletion.find({
            memberId: { $in: memberIds }
        }).populate("promptSetId", "promptset_title main_topic secondary_topics").lean();

        // ✅ Fetch all unit completion notes for the team
        const notes = await Notes.find({
            memberID: { $in: memberIds }
        }).lean();

        // ✅ Fetch all contributed units (articles, videos, etc.) by the team
        const [articles, videos, interviews, exercises, templates, promptSets] = await Promise.all([
            Article.find({ "author.id": { $in: memberIds } }).select("article_title main_topic secondary_topics author").lean(),
            Video.find({ "author.id": { $in: memberIds } }).select("video_title main_topic secondary_topics author").lean(),
            Interview.find({ "author.id": { $in: memberIds } }).select("interview_title main_topic secondary_topics author").lean(),
            Exercise.find({ "author.id": { $in: memberIds } }).select("exercise_title main_topic secondary_topics author").lean(),
            Template.find({ "author.id": { $in: memberIds } }).select("template_title main_topic secondary_topics author").lean(),
            PromptSet.find({ "author.id": { $in: memberIds } }).select("promptset_title main_topic secondary_topics author").lean()
        ]);

        // ✅ Aggregate data for the whole team
        const teamData = {
            promptSetsCompleted: promptCompletions.map(p => ({
                name: p.promptSetId?.promptset_title || "Unknown Prompt Set",
                dateCompleted: p.completedAt
            })),
            badgesEarned: promptCompletions.flatMap(p =>
                p.earnedBadge ? [{ badgeImage: p.earnedBadge.image, badgeName: p.earnedBadge.name }] : []
            ),
            unitsCompleted: await Promise.all(notes.map(async (n) => {
                return await resolveUnitDetails(n.unitID);
            })),
            unitsContributed: [
                ...articles.map(unit => ({
                    unitTitle: unit.article_title,
                    unitType: "Article",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                })),
                ...videos.map(unit => ({
                    unitTitle: unit.video_title,
                    unitType: "Video",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                })),
                ...interviews.map(unit => ({
                    unitTitle: unit.interview_title,
                    unitType: "Interview",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                })),
                ...exercises.map(unit => ({
                    unitTitle: unit.exercise_title,
                    unitType: "Exercise",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                })),
                ...templates.map(unit => ({
                    unitTitle: unit.template_title,
                    unitType: "Template",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                })),
                ...promptSets.map(unit => ({
                    unitTitle: unit.promptset_title,
                    unitType: "Prompt Set",
                    topics: [unit.main_topic, ...(unit.secondary_topics || [])]
                }))
            ],
            topicsEngaged: [
                ...promptCompletions.flatMap(p => [p.promptSetId?.main_topic, ...(p.promptSetId?.secondary_topics || [])]),
                ...articles.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])]),
                ...videos.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])]),
                ...interviews.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])]),
                ...exercises.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])]),
                ...templates.flatMap(unit => [unit.main_topic, ...(unit.secondary_topics || [])])
            ]
        };

        res.render("report_views/teamengagement", {
            layout: "dashboardlayout",
            leaderGroupName: leader.groupName,
            teamEngagementReports: [teamData] // Pass as an array to match Handlebars expectations
        });

    } catch (err) {
        console.error("❌ Error loading Team Engagement Report:", err);
        res.status(500).send("Server error");
    }
};




const getUnitsCompletedReport = async (req, res) => {
    try {
        console.log("✅ Fetching Units Completed Report...");

        // ✅ Fetch leader info
        const leader = await Leader.findById(req.user.id).select("groupName").lean();
        if (!leader) {
            console.error("❌ Leader not found.");
            return res.status(403).json({ error: "Access denied", message: "Leader not found." });
        }

        // ✅ Fetch all group members under the leader
        const members = await GroupMember.find({ groupId: req.user.id }).select("_id").lean();
        if (!members.length) {
            console.warn("⚠️ No group members found.");
        }

        const memberIds = members.map(m => m._id);

        // ✅ Fetch all notes (units completed) by these members
        const notes = await Notes.find({ memberID: { $in: memberIds } }).lean();

        // ✅ Organize data for the report
        const reportData = await Promise.all(notes.map(async (note) => {
            const unitDetails = await resolveUnitDetails(note.unitID);
            const member = await GroupMember.findById(note.memberID).select("name").lean() ||
                           await Leader.findById(note.memberID).select("groupLeaderName").lean();
            const memberName = member?.name || member?.groupLeaderName || "Unknown Member";

            return {
                unitTitle: unitDetails.unitTitle,
                unitType: unitDetails.unitType,
                main_topic: unitDetails.main_topic,
                secondary_topics: unitDetails.secondary_topics,
                completedBy: [{
                    memberName,
                    dateCompleted: note.createdAt
                }],
                memberNotes: [{
                    memberName,
                    notes: [{
                        content: note.note_content,
                        dateSubmitted: note.createdAt
                    }]
                }]
            };
        }));

        res.render("report_views/unitscompleted", {
            layout: "dashboardlayout",
            leaderGroupName: leader.groupName,
            unitsCompletedReports: reportData
        });

    } catch (err) {
        console.error("❌ Error loading Units Completed Report:", err);
        res.status(500).send("Server error");
    }

    
};

const getIndividualPromptSetCompletionReport = async (req, res) => {
  try {
    console.log("✅ Fetching Individual Prompt Set Completion Report...");

    const memberId = req.user._id;

    // ✅ Find all prompt set completions for the logged-in member
    const completions = await PromptSetCompletion.find({ memberId })
      .populate("promptSetId")
      .lean();

    const reportData = await Promise.all(completions.map(async (completion) => {
      const promptSet = completion.promptSetId;
      if (!promptSet) return null;

      const prompts = Array.from({ length: 20 }, (_, index) => ({
        promptNumber: `Prompt ${index + 1}`,
        promptHeadline: promptSet[`prompt_headline${index + 1}`] || "No headline",
        promptText: promptSet[`Prompt${index + 1}`] || "No prompt text available"
      }));

      return {
        promptSetTitle: promptSet.promptset_title,
        main_topic: promptSet.main_topic,
        secondary_topics: promptSet.secondary_topics || [],
        purpose: promptSet.purpose || "No purpose provided",
        characteristics: promptSet.characteristics || [],
        targetAudience: promptSet.target_audience || "No audience specified",
        dateCompleted: completion.completedAt,
        prompts,
        promptNotes: await Promise.all(completion.notes.map(async (note, index) => ({
          promptNumber: `Prompt ${index + 1}`,
          notes: [{
            content: note
          }]
        })))
      };
    }));

    res.render("report_views/individual_promptsets_completed", {
      layout: "dashboardlayout",
      promptSetsCompletedReports: reportData.filter(Boolean)
    });

  } catch (err) {
    console.error("❌ Error loading individual prompt set completion report:", err);
    res.status(500).render("member_form_views/error", {
      layout: "memberformlayout",
      title: "Report Error",
      errorMessage: "We couldn't load your prompt set completion report. Please try again later."
    });
  }
};

const getGroupMemberPromptSetCompletionReport = async (req, res) => {
  try {
    console.log("✅ Fetching Group Member Prompt Set Completion Report...");

    const memberId = req.user._id;

    // ✅ Find all prompt set completions for the logged-in group member
    const completions = await PromptSetCompletion.find({ memberId })
      .populate("promptSetId")
      .lean();

    const reportData = await Promise.all(completions.map(async (completion) => {
      const promptSet = completion.promptSetId;
      if (!promptSet) return null;

      const prompts = Array.from({ length: 20 }, (_, index) => ({
        promptNumber: `Prompt ${index + 1}`,
        promptHeadline: promptSet[`prompt_headline${index + 1}`] || "No headline",
        promptText: promptSet[`Prompt${index + 1}`] || "No prompt text available"
      }));

      return {
        promptSetTitle: promptSet.promptset_title,
        main_topic: promptSet.main_topic,
        secondary_topics: promptSet.secondary_topics || [],
        purpose: promptSet.purpose || "No purpose provided",
        characteristics: promptSet.characteristics || [],
        targetAudience: promptSet.target_audience || "No audience specified",
        dateCompleted: completion.completedAt,
        prompts,
        promptNotes: await Promise.all(completion.notes.map(async (note, index) => ({
          promptNumber: `Prompt ${index + 1}`,
          notes: [{
            content: note
          }]
        })))
      };
    }));

    res.render("report_views/groupmember_promptsets_completed", {
      layout: "dashboardlayout",
      promptSetsCompletedReports: reportData.filter(Boolean)
    });

  } catch (err) {
    console.error("❌ Error loading group member prompt set completion report:", err);
    res.status(500).render("groupmember_form_views/error", {
      layout: "groupmemberformlayout",
      title: "Report Error",
      errorMessage: "We couldn't load your prompt set completion report. Please try again later."
    });
  }
};



module.exports = {
  getMemberEngagementReport,
  getPromptSetsCompletedReport,
  getTeamEngagementReport,
  getUnitsCompletedReport,
  getIndividualPromptSetCompletionReport,
getGroupMemberPromptSetCompletionReport
};
