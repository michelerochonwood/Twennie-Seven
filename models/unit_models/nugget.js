const mongoose = require('mongoose');

const NuggetMonitoringNoteSchema = new mongoose.Schema({
  note: {
    type: String,
    required: true,
    trim: true
  },
  addedBy: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    refPath: 'monitoringNotes.addedByModel'
  },
  addedByModel: {
    type: String,
    enum: ['leader', 'group_member', 'member'],
    required: true
  },
  addedByNameSnapshot: {
    type: String,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { _id: true });

const NuggetSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  client: { type: String, required: true, trim: true },

  horizon: {
    type: String,
    enum: ['1y', '3y', '5y'],
    required: true
  },

  discipline: {
    type: String,
    enum: [
      'Architecture',
      'Bridges',
      'Buildings',
      'Electrical',
      'Environmental',
      'Geotechnical',
      'Hydrology',
      'Interior Design',
      'Landscape Architecture',
      'Land Development',
      'Mechanical',
      'Planning',
      'Transit',
      'Transportation',
      'Water and Wastewater',
      'Other'
    ],
    required: true,
    trim: true
  },

  region: {
    type: String,
    enum: [
      'Northwestern',
      'Northeastern',
      'Central',
      'Eastern',
      'Southwestern',
      'Prairies',
      'BC',
      'Quebec',
      'Maritimes',
      'Nunavut, NWT, and the Yukon',
      'Other'
    ],
    required: true,
    trim: true
  },

  estimatedValue: {
    bucket: {
      type: String,
      enum: [
        '<$100K',
        '$100K - $1M',
        '$1M - $10M',
        '>$10M',
        'unknown'
      ],
      default: 'unknown'
    },
    currency: {
      type: String,
      default: 'CAD',
      trim: true
    }
  },

  projectDeliveryType: {
    type: String,
    enum: [
      'design',
      'design-build',
      'CMAR',
      'P3',
      'DBFM',
      'DBF',
      'unknown',
      'Other'
    ],
    default: 'unknown'
  },

  originalSource: {
    label: { type: String, required: true, trim: true },
    url: { type: String, trim: true }
  },

  likelihood: {
    type: Number,
    min: 0,
    max: 100,
    default: 50
  },

  notes: {
    type: String,
    trim: true
  },

  monitoringNotes: {
    type: [NuggetMonitoringNoteSchema],
    default: []
  },

  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Member',
    index: true
  },

  visibility: {
    type: String,
    enum: ['team_only', 'organization_only', 'all_members'],
    default: 'team_only',
    index: true
  }
}, { timestamps: true });

NuggetSchema.index({
  title: 'text',
  client: 'text',
  region: 'text',
  discipline: 'text'
});

NuggetSchema.index({ horizon: 1, likelihood: -1 });
NuggetSchema.index({ 'estimatedValue.bucket': 1 });
NuggetSchema.index({ 'monitoringNotes.createdAt': -1 });

module.exports = mongoose.model('Nugget', NuggetSchema);