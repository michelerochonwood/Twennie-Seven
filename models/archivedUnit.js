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
 * - Archive visibility is private to the user who archived it
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
  'leader_assigned'
];

const archivedUnitSchema = new mongoose.Schema({
  /**
   * The user who performed the archive action.
   * Archive pages should mainly query by this field.
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
   * The underlying Tag record this dashboard item came from.
   */
  tagId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Tag',
    required: true,
    index: true
  },

  /**
   * The specific unit that was visible on the dashboard.
   * Important because a Tag can hold multiple associatedUnits.
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
   * Whether this archived dashboard item was:
   * - self assigned by the current user
   * - assigned by a leader to a specific group member
   */
  archiveScope: {
    type: String,
    required: true,
    enum: ARCHIVE_SCOPES,
    index: true
  },

  /**
   * Original tag ownership
   */
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true
  },

  createdByModel: {
    type: String,
    required: true,
    enum: ['member', 'group_member', 'leader']
  },

  /**
   * Assignment target details.
   * For self-assigned items, assignedToMember will usually be the same as
   * archivedBy, but we store it explicitly because completion/instructions live
   * at the assignment-row level in Tag.assignedTo[].
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
   * Unit display snapshot
   * Stored so archive views are stable even if unit titles later change.
   */
  titleSnapshot: {
    type: String,
    required: true,
    trim: true
  },

  mainTopicSnapshot: {
    type: String,
    trim: true,
    default: ''
  },

  secondaryTopicsSnapshot: [{
    type: String,
    trim: true
  }],

  /**
   * Optional display metadata for special unit types
   * (badge name, client, region, discipline, etc.)
   */
  snapshotMeta: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
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
 * Useful for archive filtering by type within a user's archive
 */
archivedUnitSchema.index({ archivedBy: 1, unitType: 1, archivedAt: -1 });

/**
 * Prevent duplicate archive entries for the same visible dashboard instance.
 *
 * Notes:
 * - One Tag can hold multiple units
 * - One leader-created Tag can be assigned to multiple members
 * - So uniqueness has to include archivedBy + tagId + unitId + assignedToMember
 *
 * For self-assigned items, assignedToMember may be null.
 */
archivedUnitSchema.index(
  { archivedBy: 1, tagId: 1, unitId: 1, assignedToMember: 1 },
  { unique: true }
);

module.exports =
  mongoose.models.ArchivedUnit ||
  mongoose.model('ArchivedUnit', archivedUnitSchema);