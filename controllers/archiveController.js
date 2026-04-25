// controllers/archiveController.js

const ArchivedUnit = require('../models/archivedUnit');
const Tag = require('../models/tag');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Note = require('../models/notes/notes');
const topicsData = require('../public/data/topics.json');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const PromptSet = require('../models/unit_models/promptset');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');


const topicSummaryMap = new Map(
  (topicsData.topics || []).map(t => [t.title, t.longSummary])
);

const {
  canonicalUnitType
} = require('./tagController');

/**
 * Resolve the user model string used throughout the app:
 * 'member' | 'group_member' | 'leader'
 */
async function getUserModel(userId) {
  if (await Member.exists({ _id: userId })) return 'member';
  if (await Leader.exists({ _id: userId })) return 'leader';
  if (await GroupMember.exists({ _id: userId })) return 'group_member';
  return null;
}

/**
 * Resolve a display name snapshot for archive rendering
 */
async function getUserNameSnapshot(userId) {
  const [groupMember, leader, member] = await Promise.all([
    GroupMember.findById(userId).select('name').lean(),
    Leader.findById(userId).select('groupLeaderName username').lean(),
    Member.findById(userId).select('username').lean()
  ]);

  if (groupMember?.name) return groupMember.name;
  if (leader?.groupLeaderName) return leader.groupLeaderName;
  if (leader?.username) return leader.username;
  if (member?.username) return member.username;
  return '';
}

exports.archiveUnit = async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.status(401).json({ message: 'Login required.' });
    }

    const { tagId, unitId, unitType, assignedToMemberId } = req.body;

    if (!tagId || !unitId || !unitType) {
      return res.status(400).json({
        message: 'tagId, unitId, and unitType are required.'
      });
    }

    const normalizedType = canonicalUnitType(unitType);
    const archiverId = String(req.user._id);

    const [tag, archiverModel] = await Promise.all([
      Tag.findById(tagId),
      getUserModel(req.user._id)
    ]);

    if (!tag) {
      return res.status(404).json({ message: 'Tag not found.' });
    }

    if (!archiverModel) {
      return res.status(403).json({ message: 'Unable to determine user type.' });
    }

    // Confirm the requested unit is actually on this tag
    const associatedUnit = (tag.associatedUnits || []).find(
      u => String(u.item) === String(unitId) && u.unitType === normalizedType
    );

    if (!associatedUnit) {
      return res.status(404).json({
        message: 'This unit is not associated with the specified assignment.'
      });
    }

    const tagCreatorId = String(tag.createdBy);
    const isTagCreator = tagCreatorId === archiverId;

    // When assignedToMemberId is supplied, this is a leader archiving a specific assignee row
    const targetAssignedMemberId = assignedToMemberId
      ? String(assignedToMemberId)
      : archiverId;

    const assignmentRow = (tag.assignedTo || []).find(
      a => String(a.member) === targetAssignedMemberId
    );

    /**
     * Permission logic
     *
     * Case A: Leader archives a specific group-member assignment they created
     * Case B: User archives their own dashboard item
     */
    let archiveScope = 'self_assigned';

    if (assignedToMemberId) {
      // Leader-assigned archive path
      const isLeader = archiverModel === 'leader';
      if (!isLeader) {
        return res.status(403).json({
          message: 'Only leaders can archive assignments for other members.'
        });
      }

      if (!isTagCreator) {
        return res.status(403).json({
          message: 'Only the creating leader can archive this assigned item.'
        });
      }

      if (!assignmentRow) {
        return res.status(404).json({
          message: 'Assigned member record not found on this tag.'
        });
      }

      archiveScope = 'leader_assigned';
} else {
  const isAssignedToMe = !!assignmentRow;

  if (!isTagCreator && !isAssignedToMe) {
    return res.status(403).json({
      message: 'You can only archive your own active dashboard items.'
    });
  }

  archiveScope = 'self_assigned';
}

const [assignedToModel, assignedToNameSnapshot] = await Promise.all([
  getUserModel(targetAssignedMemberId),
  getUserNameSnapshot(targetAssignedMemberId)
]);

    // Prevent duplicate archive rows for the same visible dashboard instance
    const existingArchive = await ArchivedUnit.findOne({
      archivedBy: req.user._id,
      tagId,
      unitId,
      assignedToMember: targetAssignedMemberId || null
    }).lean();

    if (existingArchive) {
      return res.status(200).json({
        ok: true,
        alreadyArchived: true
      });
    }

await ArchivedUnit.create({
  archivedBy: req.user._id,
  archivedByModel: archiverModel,

  tagId,
  unitId,
  unitType: normalizedType,

  archiveScope,

  createdBy: tag.createdBy,
  createdByModel: tag.createdByModel,

  assignedToMember: targetAssignedMemberId || null,
  assignedToModel: assignedToModel || null,
  assignedToNameSnapshot: assignedToNameSnapshot || '',
  assignedInstructionsSnapshot: assignmentRow?.instructions || '',
  assignedCompletedAtSnapshot: assignmentRow?.completedAt || null,

  originallyAssignedAt: tag.createdAt || null,
  archivedAt: new Date()
});

    /**
     * Remove from ACTIVE dashboard state
     *
     * Leader-assigned:
     *   remove only the targeted assignee row
     *
     * Self-assigned:
     *   remove only this user's assignment row if present.
     *   If the user is also the tag creator and this unit is only present for
     *   that self-assigned dashboard item, remove the unit association too.
     */
if (archiveScope === 'leader_assigned') {
  tag.assignedTo = (tag.assignedTo || []).filter(
    a => String(a.member) !== targetAssignedMemberId
  );
} else {
  tag.assignedTo = (tag.assignedTo || []).filter(
    a => String(a.member) !== archiverId
  );

  const hasRemainingAssignees = (tag.assignedTo || []).length > 0;

  if (isTagCreator && !hasRemainingAssignees) {
    tag.associatedUnits = (tag.associatedUnits || []).filter(
      u => !(String(u.item) === String(unitId) && u.unitType === normalizedType)
    );
  }
}

    const isNowEmpty =
      (tag.associatedUnits?.length || 0) === 0 &&
      (tag.assignedTo?.length || 0) === 0 &&
      (tag.associatedTopics?.length || 0) === 0;

    if (isNowEmpty) {
      await Tag.findByIdAndDelete(tag._id);
    } else {
      await tag.save();
    }

    return res.status(200).json({ ok: true });

  } catch (e) {
    console.error('❌ archiveUnit error:', e);

    // Duplicate unique-index hit should not look like a crash
    if (e && e.code === 11000) {
      return res.status(200).json({
        ok: true,
        alreadyArchived: true
      });
    }

    return res.status(500).json({ message: 'Internal server error' });
  }
};

exports.renderLeaderArchive = async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.redirect('/auth/login');
    }

    const leaderId = String(req.user._id);

    const leader = await Leader.findById(leaderId)
      .select('groupLeaderName members')
      .lean();

    if (!leader) {
      return res.status(404).render('error', {
        title: 'Error',
        errorMessage: 'Leader not found.'
      });
    }

    const groupMemberIds = (leader.members || []).map(m => String(m));

    const archiveRows = await ArchivedUnit.find({
      $or: [
        { archivedBy: leaderId },
        { archivedBy: { $in: groupMemberIds } }
      ]
    })
      .sort({ archivedAt: -1 })
      .lean();

    const archiveTopicsMap = new Map();
    const archivedNuggets = [];
    const archivedMissions = [];

for (const row of archiveRows) {
let unitDoc = null;
let title = 'Untitled unit';
let mainTopic = 'No Topic Assigned';
let summary = '';
let unitAuthorName = '';
let viewPath = '';
let notesPreview = '';
let archiveNoteInstruction = '';

      if (row.unitType === 'article') {
        const Article = require('../models/unit_models/article');
        unitDoc = await Article.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.article_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.article_summary || '';
          viewPath = `/unitviews/articles/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'video') {
        const Video = require('../models/unit_models/video');
        unitDoc = await Video.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.video_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.video_summary || '';
          viewPath = `/unitviews/videos/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'promptset') {
        const PromptSet = require('../models/unit_models/promptset');
        unitDoc = await PromptSet.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.promptset_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.promptset_summary || '';
          viewPath = `/unitviews/promptsets/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'interview') {
        const Interview = require('../models/unit_models/interview');
        unitDoc = await Interview.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.interview_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.interview_summary || '';
          viewPath = `/unitviews/interviews/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'exercise') {
        const Exercise = require('../models/unit_models/exercise');
        unitDoc = await Exercise.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.exercise_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.exercise_summary || '';
          viewPath = `/unitviews/exercises/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'template') {
        const Template = require('../models/unit_models/template');
        unitDoc = await Template.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.template_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.template_summary || '';
          viewPath = `/unitviews/templates/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'upcoming') {
        const Upcoming = require('../models/unit_models/upcoming');
        unitDoc = await Upcoming.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/upcomings/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'nugget') {
        const Nugget = require('../models/unit_models/nugget');
        unitDoc = await Nugget.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.title || title;
          mainTopic = unitDoc.main_topic || unitDoc.discipline || unitDoc.client || unitDoc.region || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/nuggets/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'mission') {
        const Mission = require('../models/unit_models/mission');
        unitDoc = await Mission.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.mission_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/missions/view/${unitDoc._id}`;
        }
      }

if (unitDoc?.author?.id || unitDoc?.author) {
  const authorId = unitDoc.author.id || unitDoc.author;
  const authorName = await getUserNameSnapshot(authorId);
  unitAuthorName = authorName || '';
}

if (row.unitType === 'promptset' && row.assignedToMember && row.unitId) {
  const completion = await PromptSetCompletion.findOne({
    memberId: row.assignedToMember,
    promptSetId: row.unitId
  })
    .sort({ completedAt: -1, createdAt: -1 })
    .lean();

  notesPreview =
    completion?.finalNotes ||
    completion?.notes?.[19] ||
    '';

  archiveNoteInstruction = 'View all 20 notes in the completed prompt sets report.';

} else if (row.unitType === 'nugget') {
  notesPreview = unitDoc?.notes || '';
  archiveNoteInstruction = 'View all nugget notes in the nuggets report.';

} else if (row.assignedToMember && row.unitId) {
  const learnerNote = await Note.findOne({
    unitID: row.unitId,
    memberID: row.assignedToMember
  })
    .sort({ updatedAt: -1, createdAt: -1 })
    .lean();

  if (learnerNote?.note_content) {
    notesPreview = learnerNote.note_content;
  }
}

const archiveCard = {
  ...row,
  titleSnapshot: title,
  mainTopicSnapshot: mainTopic,
  summarySnapshot: summary,
  unitAuthorName,
  completedByName: row.assignedToNameSnapshot || '',
  completedWhenFormatted: row.assignedCompletedAtSnapshot
    ? new Date(row.assignedCompletedAtSnapshot).toLocaleDateString('en-CA', {
        year: 'numeric',
        month: 'short',
        day: '2-digit'
      })
    : '',
  archivedAtFormatted: row.archivedAt
    ? new Date(row.archivedAt).toLocaleDateString('en-CA', {
        year: 'numeric',
        month: 'short',
        day: '2-digit'
      })
    : '',
  archivedByNameSnapshot: row.assignedToNameSnapshot || '',
  notesPreview,
  archiveNoteInstruction,
  viewPath,
  reportPath: '/reports/leaderreport'
};

if (row.unitType === 'nugget') {
  archivedNuggets.push(archiveCard);
} else if (row.unitType === 'mission') {
  archivedMissions.push(archiveCard);
} else {
  const topicTitle = mainTopic || 'No Topic Assigned';

  if (!archiveTopicsMap.has(topicTitle)) {
    archiveTopicsMap.set(topicTitle, []);
  }

  archiveTopicsMap.get(topicTitle).push(archiveCard);
}
    }

    const archiveTopics = Array.from(archiveTopicsMap.entries())
      .map(([topicTitle, archivedItems]) => ({
        topicTitle,
        topicLongSummary: topicSummaryMap.get(topicTitle) || '',
        archivedItems
      }))
      .sort((a, b) => a.topicTitle.localeCompare(b.topicTitle));

return res.render('archiveviews/leader_archive', {
  layout: 'dashboardlayout',
  title: 'Learning Archive',
  archiveTopics,
  archivedNuggets,
  archivedMissions
});

  } catch (err) {
    console.error('❌ renderLeaderArchive error:', err);
    return res.status(500).render('error', {
      title: 'Error',
      errorMessage: 'Could not load the archive.'
    });
  }
};

exports.renderGroupMemberArchive = async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.redirect('/auth/login');
    }

    const groupMemberId = String(req.user._id);

const archiveRows = await ArchivedUnit.find({
  $or: [
    { archivedBy: groupMemberId },
    { assignedToMember: groupMemberId }
  ]
})
  .sort({ archivedAt: -1 })
  .lean();

    const archiveTopicsMap = new Map();

    for (const row of archiveRows) {
      let unitDoc = null;
      let title = 'Untitled unit';
      let mainTopic = 'No Topic Assigned';
      let summary = '';
      let unitAuthorName = '';
      let viewPath = '';
      let notesPreview = '';
      let archiveNoteInstruction = '';

      if (row.unitType === 'article') {
        const Article = require('../models/unit_models/article');
        unitDoc = await Article.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.article_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.article_summary || '';
          viewPath = `/unitviews/articles/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'video') {
        const Video = require('../models/unit_models/video');
        unitDoc = await Video.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.video_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.video_summary || '';
          viewPath = `/unitviews/videos/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'promptset') {
        const PromptSet = require('../models/unit_models/promptset');
        unitDoc = await PromptSet.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.promptset_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.promptset_summary || '';
          viewPath = `/unitviews/promptsets/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'interview') {
        const Interview = require('../models/unit_models/interview');
        unitDoc = await Interview.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.interview_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.interview_summary || '';
          viewPath = `/unitviews/interviews/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'exercise') {
        const Exercise = require('../models/unit_models/exercise');
        unitDoc = await Exercise.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.exercise_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.exercise_summary || '';
          viewPath = `/unitviews/exercises/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'template') {
        const Template = require('../models/unit_models/template');
        unitDoc = await Template.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.template_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.template_summary || '';
          viewPath = `/unitviews/templates/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'upcoming') {
        const Upcoming = require('../models/unit_models/upcoming');
        unitDoc = await Upcoming.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/upcomings/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'nugget') {
        const Nugget = require('../models/unit_models/nugget');
        unitDoc = await Nugget.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.title || title;
          mainTopic = unitDoc.main_topic || unitDoc.discipline || unitDoc.client || unitDoc.region || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/nuggets/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'mission') {
        const Mission = require('../models/unit_models/mission');
        unitDoc = await Mission.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.mission_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/missions/view/${unitDoc._id}`;
        }
      }

      if (unitDoc?.author?.id || unitDoc?.author) {
        const authorId = unitDoc.author.id || unitDoc.author;
        const authorName = await getUserNameSnapshot(authorId);
        unitAuthorName = authorName || '';
      }

      if (row.unitType === 'promptset' && row.assignedToMember && row.unitId) {
        const completion = await PromptSetCompletion.findOne({
          memberId: row.assignedToMember,
          promptSetId: row.unitId
        })
          .sort({ completedAt: -1, createdAt: -1 })
          .lean();

        notesPreview =
          completion?.finalNotes ||
          completion?.notes?.[19] ||
          '';

        archiveNoteInstruction = 'View all 20 notes in the completed prompt sets report.';

      } else if (row.unitType === 'nugget') {
        notesPreview = unitDoc?.notes || '';
        archiveNoteInstruction = 'View all nugget notes in the nuggets report.';

      } else if (row.assignedToMember && row.unitId) {
        const learnerNote = await Note.findOne({
          unitID: row.unitId,
          memberID: row.assignedToMember
        })
          .sort({ updatedAt: -1, createdAt: -1 })
          .lean();

        if (learnerNote?.note_content) {
          notesPreview = learnerNote.note_content;
        }
      }

      const topicTitle = mainTopic || 'No Topic Assigned';

      if (!archiveTopicsMap.has(topicTitle)) {
        archiveTopicsMap.set(topicTitle, []);
      }

      archiveTopicsMap.get(topicTitle).push({
        ...row,
        titleSnapshot: title,
        mainTopicSnapshot: mainTopic,
        summarySnapshot: summary,
        unitAuthorName,
        completedByName: row.assignedToNameSnapshot || '',
        completedWhenFormatted: row.assignedCompletedAtSnapshot
          ? new Date(row.assignedCompletedAtSnapshot).toLocaleDateString('en-CA', {
              year: 'numeric',
              month: 'short',
              day: '2-digit'
            })
          : '',
        archivedAtFormatted: row.archivedAt
          ? new Date(row.archivedAt).toLocaleDateString('en-CA', {
              year: 'numeric',
              month: 'short',
              day: '2-digit'
            })
          : '',
        notesPreview,
        archiveNoteInstruction,
        viewPath,
        reportPath: '/reports/mylearningnotes'
      });
    }

    const archiveTopics = Array.from(archiveTopicsMap.entries())
      .map(([topicTitle, archivedItems]) => ({
        topicTitle,
        topicLongSummary: topicSummaryMap.get(topicTitle) || '',
        archivedItems
      }))
      .sort((a, b) => a.topicTitle.localeCompare(b.topicTitle));

    return res.render('archiveviews/groupmember_archive', {
      layout: 'dashboardlayout',
      title: 'Learning Archive',
      archiveTopics
    });

  } catch (err) {
    console.error('❌ renderGroupMemberArchive error:', err);
    return res.status(500).render('error', {
      title: 'Error',
      errorMessage: 'Could not load the archive.'
    });
  }
};

exports.archiveCompletedPromptSet = async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.status(401).json({ message: 'Login required.' });
    }

    const { promptSetId, completionId, assignedToMemberId } = req.body;

    if (!promptSetId) {
      return res.status(400).json({
        message: 'promptSetId is required.'
      });
    }

    const archiverId = String(req.user._id);
    const archiverModel = await getUserModel(req.user._id);

    if (!archiverModel) {
      return res.status(403).json({
        message: 'Unable to determine user type.'
      });
    }

    const targetMemberId = assignedToMemberId
      ? String(assignedToMemberId)
      : archiverId;

    const completionQuery = completionId
      ? { _id: completionId, memberId: targetMemberId, promptSetId }
      : { memberId: targetMemberId, promptSetId };

    const completion = await PromptSetCompletion.findOne(completionQuery)
      .sort({ completedAt: -1, createdAt: -1 })
      .lean();

    if (!completion) {
      return res.status(404).json({
        message: 'Completed prompt set record not found.'
      });
    }

    const promptSet = await PromptSet.findById(promptSetId).lean();

    if (!promptSet) {
      return res.status(404).json({
        message: 'Prompt set not found.'
      });
    }

const assignment = await AssignPromptSet.findOne({
  promptSetId,
  assignedMemberIds: targetMemberId
}).lean();

const registration = await PromptSetRegistration.findOne({
  promptSetId,
  memberId: targetMemberId
}).lean();

    const assignedToModel = await getUserModel(targetMemberId);
    const assignedToNameSnapshot = await getUserNameSnapshot(targetMemberId);

    const existingArchive = await ArchivedUnit.findOne({
      archivedBy: req.user._id,
      unitId: promptSetId,
      unitType: 'promptset',
      assignedToMember: targetMemberId
    }).lean();

    if (existingArchive) {
      return res.status(200).json({
        ok: true,
        alreadyArchived: true
      });
    }

await ArchivedUnit.create({
  archivedBy: req.user._id,
  archivedByModel: archiverModel,

  tagId: null,
  unitId: promptSetId,
  unitType: 'promptset',

  archiveScope: assignment ? 'promptset_assigned' : 'promptset_self_completed',

  createdBy: assignment?.groupLeaderId || promptSet.author?.id || promptSet.author || targetMemberId,
  createdByModel: assignment?.groupLeaderId ? 'leader' : archiverModel,

  assignedToMember: targetMemberId,
  assignedToModel: assignedToModel || null,
  assignedToNameSnapshot: assignedToNameSnapshot || '',

  assignedInstructionsSnapshot: assignment?.leaderNotes || registration?.leaderNotes || '',
  assignedCompletedAtSnapshot: completion.completedAt || null,

  originallyAssignedAt:
    assignment?.assignDate ||
    assignment?.createdAt ||
    registration?.registeredAt ||
    registration?.createdAt ||
    null,

  archivedAt: new Date()
});

    return res.status(200).json({ ok: true });

  } catch (e) {
    console.error('❌ archiveCompletedPromptSet error:', e);

    if (e && e.code === 11000) {
      return res.status(200).json({
        ok: true,
        alreadyArchived: true
      });
    }

    return res.status(500).json({
      message: 'Internal server error'
    });
  }
};

exports.renderMemberArchive = async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      return res.redirect('/auth/login');
    }

    const memberId = String(req.user._id);

    const member = await Member.findById(memberId)
      .select('_id username')
      .lean();

    if (!member) {
      return res.status(404).render('error', {
        title: 'Error',
        errorMessage: 'Member not found.'
      });
    }

    const archiveRows = await ArchivedUnit.find({
      archivedBy: memberId
    })
      .sort({ archivedAt: -1 })
      .lean();

    const archiveTopicsMap = new Map();

    for (const row of archiveRows) {
      let unitDoc = null;
      let title = 'Untitled unit';
      let mainTopic = 'No Topic Assigned';
      let summary = '';
      let unitAuthorName = '';
      let viewPath = '';
      let notesPreview = '';
      let archiveNoteInstruction = '';

      if (row.unitType === 'article') {
        const Article = require('../models/unit_models/article');
        unitDoc = await Article.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.article_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.article_summary || '';
          viewPath = `/unitviews/articles/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'video') {
        const Video = require('../models/unit_models/video');
        unitDoc = await Video.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.video_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.video_summary || '';
          viewPath = `/unitviews/videos/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'promptset') {
        const PromptSet = require('../models/unit_models/promptset');
        unitDoc = await PromptSet.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.promptset_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.promptset_summary || '';
          viewPath = `/unitviews/promptsets/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'interview') {
        const Interview = require('../models/unit_models/interview');
        unitDoc = await Interview.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.interview_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.interview_summary || '';
          viewPath = `/unitviews/interviews/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'exercise') {
        const Exercise = require('../models/unit_models/exercise');
        unitDoc = await Exercise.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.exercise_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.exercise_summary || '';
          viewPath = `/unitviews/exercises/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'template') {
        const Template = require('../models/unit_models/template');
        unitDoc = await Template.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.template_title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || unitDoc.template_summary || '';
          viewPath = `/unitviews/templates/view/${unitDoc._id}`;
        }
      } else if (row.unitType === 'upcoming') {
        const Upcoming = require('../models/unit_models/upcoming');
        unitDoc = await Upcoming.findById(row.unitId).lean();
        if (unitDoc) {
          title = unitDoc.title || title;
          mainTopic = unitDoc.main_topic || mainTopic;
          summary = unitDoc.summary || '';
          viewPath = `/unitviews/upcomings/view/${unitDoc._id}`;
        }
      }

      if (unitDoc?.author?.id || unitDoc?.author) {
        const authorId = unitDoc.author.id || unitDoc.author;
        const authorName = await getUserNameSnapshot(authorId);
        unitAuthorName = authorName || '';
      }

      if (row.unitType === 'promptset' && row.assignedToMember && row.unitId) {
        const completion = await PromptSetCompletion.findOne({
          memberId: row.assignedToMember,
          promptSetId: row.unitId
        })
          .sort({ completedAt: -1, createdAt: -1 })
          .lean();

        notesPreview =
          completion?.finalNotes ||
          completion?.notes?.[19] ||
          '';

        archiveNoteInstruction = 'View all 20 notes in the completed prompt sets report.';

      } else if (row.assignedToMember && row.unitId) {
        const learnerNote = await Note.findOne({
          unitID: row.unitId,
          memberID: row.assignedToMember
        })
          .sort({ updatedAt: -1, createdAt: -1 })
          .lean();

        if (learnerNote?.note_content) {
          notesPreview = learnerNote.note_content;
        }
      }

      const topicTitle = mainTopic || 'No Topic Assigned';

      if (!archiveTopicsMap.has(topicTitle)) {
        archiveTopicsMap.set(topicTitle, []);
      }

      archiveTopicsMap.get(topicTitle).push({
        ...row,
        titleSnapshot: title,
        mainTopicSnapshot: mainTopic,
        summarySnapshot: summary,
        unitAuthorName,
        completedByName: row.assignedToNameSnapshot || '',
        completedWhenFormatted: row.assignedCompletedAtSnapshot
          ? new Date(row.assignedCompletedAtSnapshot).toLocaleDateString('en-CA', {
              year: 'numeric',
              month: 'short',
              day: '2-digit'
            })
          : '',
        archivedAtFormatted: row.archivedAt
          ? new Date(row.archivedAt).toLocaleDateString('en-CA', {
              year: 'numeric',
              month: 'short',
              day: '2-digit'
            })
          : '',
        notesPreview,
        archiveNoteInstruction,
        viewPath,
        reportPath: '/reports/mylearningnotes_individual'
      });
    }

    const archiveTopics = Array.from(archiveTopicsMap.entries())
      .map(([topicTitle, archivedItems]) => ({
        topicTitle,
        topicLongSummary: topicSummaryMap.get(topicTitle) || '',
        archivedItems
      }))
      .sort((a, b) => a.topicTitle.localeCompare(b.topicTitle));

    return res.render('archiveviews/member_archive', {
      layout: 'dashboardlayout',
      title: 'Learning Archive',
      archiveTopics
    });

  } catch (err) {
    console.error('❌ renderMemberArchive error:', err);
    return res.status(500).render('error', {
      title: 'Error',
      errorMessage: 'Could not load the archive.'
    });
  }
};

