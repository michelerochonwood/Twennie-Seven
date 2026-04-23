// controllers/archiveController.js

const ArchivedUnit = require('../models/archivedUnit');
const Tag = require('../models/tag');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

const {
  canonicalUnitType,
  getUnitTitle
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
      // Self archive path
      // Allowed if:
      // - user created the tag, OR
      // - user is actually assigned on the tag
      const isAssignedToMe = !!assignmentRow;

      if (!isTagCreator && !isAssignedToMe) {
        return res.status(403).json({
          message: 'You can only archive your own active dashboard items.'
        });
      }

      archiveScope = 'self_assigned';
    }

    const [titleSnapshot, assignedToModel, assignedToNameSnapshot] = await Promise.all([
      getUnitTitle(normalizedType, unitId),
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

      titleSnapshot,
      mainTopicSnapshot: '',
      secondaryTopicsSnapshot: [],

      snapshotMeta: {},
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
      // Remove this user's assignment row if present
      tag.assignedTo = (tag.assignedTo || []).filter(
        a => String(a.member) !== archiverId
      );

      // If this user is the creator, also remove the unit association
      // so it disappears from their self-assigned active dashboard
      if (isTagCreator) {
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