const mongoose = require('mongoose');
const { Schema } = mongoose;

const OrganizationUnitSuggestionSchema = new Schema(
  {
    organization: { type: Schema.Types.ObjectId, ref: 'Organization', required: true },

    // who suggested it
    suggestedBy: { type: Schema.Types.ObjectId, ref: 'Leader', required: true },

    // who it is suggested to
    leaderId: { type: Schema.Types.ObjectId, ref: 'Leader', required: true },

    // unit being suggested
    unitId: { type: Schema.Types.ObjectId, required: true },
    unitType: { type: String, required: true, enum: ['article', 'video', 'interview', 'exercise', 'template', 'mission', 'promptset'] },

    // snapshot fields so leader dashboard doesn’t need cross-collection lookups
    unitTitle: { type: String, default: '' },
    main_topic: { type: String, default: '' },
    secondary_topic: { type: String, default: '' },

    note: { type: String, default: '' },

    status: { type: String, enum: ['pending', 'seen', 'dismissed'], default: 'pending' }
  },
  { timestamps: true }
);

OrganizationUnitSuggestionSchema.index({ leaderId: 1, status: 1, createdAt: -1 });
OrganizationUnitSuggestionSchema.index({ organization: 1, createdAt: -1 });

module.exports = mongoose.model('OrganizationUnitSuggestion', OrganizationUnitSuggestionSchema);
