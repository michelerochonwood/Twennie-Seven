// models/tag.js
const mongoose = require('mongoose');

const UNIT_TYPES = [
  'upcoming',
  'article',
  'video',
  'interview',
  'promptset',
  'exercise',
  'template',
  'microcourse',   // ← include if you use micro courses
  'microstudy',    // ← include if you use micro studies
  // 'peercoaching', // ← uncomment if/when you add it
];

const tagSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,     // global uniqueness across creators (as in your original)
    trim: true,
  },

  // Who created the tag (we store the id + a lowercase label of the model)
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  createdByModel: {
    type: String,
    required: true,
    enum: ['member', 'group_member', 'leader'], // labels (not Mongoose model names)
  },

  // Units this tag is attached to (ID + lowercase unitType label)
  associatedUnits: [{
    item: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
    unitType: {
      type: String,
      required: true,
      enum: UNIT_TYPES,
    }
  }],

  // Optional: direct topic associations
  associatedTopics: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Topic',
  }],

  // Leader assignments (as in your original)
  assignedTo: [{
    member: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'GroupMember',
      required: true,
    },
    instructions: { type: String, trim: true, default: '' },
    completedAt: { type: Date, default: null },
  }],
}, { timestamps: true });

/**
 * Static: migrate Tag.associatedUnits entries from one unit (usually 'upcoming')
 * to the newly published unit. Uses arrayFilters to update only matching elements.
 *
 * Params:
 *  - fromItemId: ObjectId|string of the "upcoming" doc
 *  - toItemId:   ObjectId|string of the new unit
 *  - toUnitType: string in UNIT_TYPES (e.g., 'article', 'video', ...)
 *  - fromUnitType: string (defaults to 'upcoming')
 */
tagSchema.statics.migrateAssociatedUnits = async function ({
  fromItemId,
  toItemId,
  toUnitType,
  fromUnitType = 'upcoming',
}) {
  if (!fromItemId || !toItemId || !toUnitType) return { modifiedCount: 0 };

  const fromId = new mongoose.Types.ObjectId(fromItemId);
  const toId   = new mongoose.Types.ObjectId(toItemId);

  const res = await this.updateMany(
    { 'associatedUnits.item': fromId, 'associatedUnits.unitType': fromUnitType },
    {
      $set: {
        'associatedUnits.$[elem].item'    : toId,
        'associatedUnits.$[elem].unitType': toUnitType,
      }
    },
    { arrayFilters: [{ 'elem.item': fromId, 'elem.unitType': fromUnitType }] }
  );

  return { modifiedCount: res.modifiedCount ?? res.nModified ?? 0 };
};

// Helpful indexes
tagSchema.index({ name: 1 }, { unique: true });
tagSchema.index({ 'associatedUnits.item': 1, 'associatedUnits.unitType': 1 });
tagSchema.index({ createdBy: 1 });

module.exports = mongoose.models.Tag || mongoose.model('Tag', tagSchema);


