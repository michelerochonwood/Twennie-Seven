const mongoose = require('mongoose');

const ConnectedUnitSchema = new mongoose.Schema({
  kind: {
    type: String,
    enum: ['article', 'video', 'interview', 'promptset', 'exercise', 'template'],
    required: true
  },
  unitId: { type: mongoose.Schema.Types.ObjectId, required: true },
  note: String
}, { _id: false });

const NuggetSchema = new mongoose.Schema({
  // Required core
  title: { type: String, required: true, trim: true },
  client: { type: String, required: true, trim: true },
  horizon: { type: String, enum: ['1y', '3y', '5y'], required: true },

  // Classification
  discipline: { type: String, trim: true },
  region: { type: String, trim: true },

  // Scale
  estimatedValue: {
    amount: { type: Number, min: 0 },
    currency: { type: String, default: 'CAD' }
  },

  // Delivery / procurement
  projectDeliveryType: {
    type: String,
    enum: ['design', 'design-build', 'CMAR', 'P3', 'DBFM', 'DBF', 'unknown'],
    default: 'unknown'
  },

  // Source
  originalSource: {
    label: { type: String, required: true, trim: true },
    url: { type: String, trim: true }
  },

  // Prioritization
  likelihood: { type: Number, min: 0, max: 100, default: 50 },

  // Cross-links
  connectedTwennieUnits: [ConnectedUnitSchema],

  // Notes
  notes: { type: String, trim: true },

  // 🔹 Ownership & visibility (needed for sections)
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Member', index: true },
  visibility: {
    type: String,
    enum: ['team_only', 'organization_only', 'all_members'],
    default: 'team_only',
    index: true
  }
}, { timestamps: true });

// Indexes
NuggetSchema.index({ title: 'text', client: 'text', region: 'text', discipline: 'text' });
NuggetSchema.index({ horizon: 1, likelihood: -1 });
NuggetSchema.index({ 'estimatedValue.amount': -1 });

module.exports = mongoose.model('Nugget', NuggetSchema);

