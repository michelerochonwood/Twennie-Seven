// models/tag.js
const mongoose = require('mongoose');

const UNIT_TYPES = [
  'upcoming', 'article', 'video', 'interview', 'promptset',
  'exercise', 'template', 'microcourse', 'microstudy'
  // 'peercoaching' // add when ready
];

const tagSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  // normalized name for uniqueness
  nameLower: {
    type: String,
    required: true,
    trim: true
  },

  // Who created the tag
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

  // Unit associations
  associatedUnits: [{
    item: { type: mongoose.Schema.Types.ObjectId, required: true },
    unitType: { type: String, required: true, enum: UNIT_TYPES }
  }],

  // Topic associations (optional)
  associatedTopics: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Topic',
  }],

  // Leader assignments
  assignedTo: [{
    member: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'GroupMember',
      required: true,
      index: true
    },
    instructions: { type: String, trim: true, default: '' },
    completedAt: { type: Date, default: null }
  }]
}, { timestamps: true });

// Normalize before validate/save
tagSchema.pre('validate', function(next) {
  if (this.name) this.nameLower = String(this.name).trim().toLowerCase();
  next();
});

/**
 * Migrate Tag.associatedUnits entries from one unit (e.g., 'upcoming') to the newly published unit.
 */
tagSchema.statics.migrateAssociatedUnits = async function ({
  fromItemId, toItemId, toUnitType, fromUnitType = 'upcoming'
}) {
  if (!fromItemId || !toItemId || !toUnitType) return { modifiedCount: 0 };

  const fromId = new mongoose.Types.ObjectId(fromItemId);
  const toId   = new mongoose.Types.ObjectId(toItemId);

  const res = await this.updateMany(
    { 'associatedUnits.item': fromId, 'associatedUnits.unitType': fromUnitType },
    { $set: { 'associatedUnits.$[e].item': toId, 'associatedUnits.$[e].unitType': toUnitType } },
    { arrayFilters: [{ 'e.item': fromId, 'e.unitType': fromUnitType }] }
  );

  return { modifiedCount: res.modifiedCount ?? res.nModified ?? 0 };
};

// Indexes
tagSchema.index({ nameLower: 1, createdBy: 1 }, { unique: true });
tagSchema.index({ 'associatedUnits.item': 1, 'associatedUnits.unitType': 1 });
tagSchema.index({ createdBy: 1 });

module.exports = mongoose.models.Tag || mongoose.model('Tag', tagSchema);



