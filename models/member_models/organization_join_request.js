const mongoose = require('mongoose');

const organizationJoinRequestSchema = new mongoose.Schema({
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true },
  leader:       { type: mongoose.Schema.Types.ObjectId, ref: 'Leader', required: true },

  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },

  requestedAt: { type: Date, default: Date.now },
  reviewedAt:  { type: Date },
  reviewedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'Leader' }, // admin who reviewed
  note:        { type: String, default: '' }
}, { timestamps: true });

organizationJoinRequestSchema.index({ organization: 1, leader: 1 }, { unique: true });

module.exports = mongoose.model('OrganizationJoinRequest', organizationJoinRequestSchema);

