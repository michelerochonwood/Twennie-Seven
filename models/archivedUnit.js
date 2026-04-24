// models/archivedUnit.js
const mongoose = require('mongoose');

/**
 * ArchivedUnit
 *
 * Represents a unit/assignment instance that was once active on a dashboard
 * but has been intentionally moved out of the active dashboard view.
 *
 * Important:
 * - Archiving affects dashboard visibility only
 * - Archiving does NOT remove the item from reporting/history
 * - Archive visibility is role-dependent:
 *   - member: their own archive
 *   - group_member: their own archive
 *   - leader: their own archive + group archive
 *
 * Archive is meant to support a CURRENT VIEW of previously assigned work,
 * not a frozen historical snapshot of the unit itself.
 */

const UNIT_TYPES = [
  'upcoming',
  'article',
  'video',
  'interview',
  'promptset',
  'exercise',
  'template',
  'mission',
  'nugget'
];

const ARCHIVE_SCOPES = [
  'self_assigned',
  'leader_assigned',
  'promptset_self_completed',
  'promptset_assigned'
];

const archivedUnitSchema = new mongoose.Schema({
  /**
   * The user who performed the archive action.
   * This is the most important field for archive visibility.
   */
  archivedBy: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true
  },

  archivedByModel: {
    type: String,
    required: true,
    enum: ['member', 'group_member', 'leader']
  },

  /**
   * Underlying Tag record this archived dashboard item came from.
   *
   * Tag-based units use this.
   * Completed prompt sets may not have a Tag, so this must be optional.
   */
  tagId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Tag',
    required: false,
    default: null,
    index: true
  },

  /**
   * The specific unit this archive item refers to.
   * Archive views will use unitId + unitType to pull the CURRENT unit data.
   */
  unitId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true
  },

  unitType: {
    type: String,
    required: true,
    enum: UNIT_TYPES,
    index: true
  },

  /**
   * Whether this was:
   * - a self-assigned dashboard item
   * - a leader-assigned item archived for a specific assignee
   * - a completed prompt set archived by the learner
   * - a leader-assigned completed prompt set archived by the learner
   */
  archiveScope: {
    type: String,
    required: true,
    enum: ARCHIVE_SCOPES,
    index: true
  },

  /**
   * Original assignment/content ownership.
   *
   * Tag-based archives generally have this from the Tag.
   * Completed prompt-set archives may derive this from AssignPromptSet.groupLeaderId,
   * PromptSet author, or may be null if unavailable.
   */
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    required: false,
    default: null,
    index: true
  },

  createdByModel: {
    type: String,
    required: false,
    enum: ['member', 'group_member', 'leader', null],
    default: null
  },

  /**
   * Assignment target details.
   * For leader-assigned items, this is the assignee.
   * For self-assigned items, this will usually match archivedBy.
   * For completed prompt sets, this should be the learner who completed it.
   */
  assignedToMember: {
    type: mongoose.Schema.Types.ObjectId,
    default: null,
    index: true
  },

  assignedToModel: {
    type: String,
    enum: ['member', 'group_member', 'leader', null],
    default: null
  },

  /**
   * Lightweight convenience fields for archive display.
   * These describe assignment/completion context, not the unit content itself.
   */
  assignedToNameSnapshot: {
    type: String,
    trim: true,
    default: ''
  },

  assignedInstructionsSnapshot: {
    type: String,
    trim: true,
    default: ''
  },

  assignedCompletedAtSnapshot: {
    type: Date,
    default: null
  },

  /**
   * Timing
   */
  originallyAssignedAt: {
    type: Date,
    default: null
  },

  archivedAt: {
    type: Date,
    default: Date.now,
    index: true
  }

}, { timestamps: true });

/**
 * Fast lookup for each user's archive page
 */
archivedUnitSchema.index({ archivedBy: 1, archivedAt: -1 });

/**
 * Useful for type-based filtering inside archives
 */
archivedUnitSchema.index({ archivedBy: 1, unitType: 1, archivedAt: -1 });

/**
 * Prevent duplicate archive entries for the same visible dashboard instance.
 *
 * Includes archiveScope so Tag-based and prompt-completion archives do not collide.
 * tagId may be null for completed prompt sets.
 */
archivedUnitSchema.index(
  { archivedBy: 1, tagId: 1, unitId: 1, assignedToMember: 1, archiveScope: 1 },
  { unique: true }
);

module.exports =
  mongoose.models.ArchivedUnit ||
  mongoose.model('ArchivedUnit', archivedUnitSchema);