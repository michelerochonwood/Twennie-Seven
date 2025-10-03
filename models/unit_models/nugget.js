// models/unit_models/nugget.js
const mongoose = require('mongoose');

const ConnectedUnitSchema = new mongoose.Schema({
  kind: {
    type: String,
    enum: ['article', 'video', 'interview', 'promptset', 'exercise', 'template'],
    required: true
  },
  unitId: { type: mongoose.Schema.Types.ObjectId, required: true }, // references the unit's _id in its own collection
  note: String
}, { _id: false });

const NuggetSchema = new mongoose.Schema({
  // Required core
  title: { type: String, required: true, trim: true },
  client: { type: String, required: true, trim: true },                // e.g., "Region of Peel" / "City of Oshawa"
  horizon: { type: String, enum: ['1y', '3y', '5y'], required: true }, // near/medium/long

  // Classification
  discipline: { type: String, trim: true },                            // free text (e.g., "water/wastewater", "architecture")
  region: { type: String, trim: true },                                // e.g., "Southern Ontario – Peel"

  // Scale
  estimatedValue: {
    amount: { type: Number, min: 0 },                                  // numeric value only
    currency: { type: String, default: 'CAD' }
  },

  // Delivery / procurement
  projectDeliveryType: {
    type: String,
    enum: ['design', 'design-build', 'CMAR', 'P3', 'DBFM', 'DBF', 'unknown'],
    default: 'unknown'
  },

  // Source (single, with optional url)
  originalSource: {
    label: { type: String, required: true, trim: true },               // e.g., "Peel Capital Budget 2025"
    url: { type: String, trim: true }                                  // optional link
  },

  // Prioritization
  likelihood: { type: Number, min: 0, max: 100, default: 50 },         // % confidence

  // Cross-links into Twennie
  connectedTwennieUnits: [ConnectedUnitSchema],

  // Free-form notes
  notes: { type: String, trim: true }
}, { timestamps: true });

// Helpful indexes for quick find/filter
NuggetSchema.index({ title: 'text', client: 'text', region: 'text', discipline: 'text' });
NuggetSchema.index({ horizon: 1, likelihood: -1 });
NuggetSchema.index({ 'estimatedValue.amount': -1 });

module.exports = mongoose.model('Nugget', NuggetSchema);
