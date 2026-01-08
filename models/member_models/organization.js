// models/org_models/organization.js
const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Organization name is required'],
      trim: true,
      maxlength: 120
    },

    // slug makes matching + URLs easy; keep unique
    slug: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      maxlength: 140
    },

    industry: {
      type: String,
      trim: true,
      maxlength: 80
    },

    // Optional: helpful later for auto-match / invitations
    domains: [{
      type: String,
      trim: true,
      lowercase: true
    }],

    isActive: {
      type: Boolean,
      default: true
    }
  },
  { timestamps: true }
);

// Fast lookup by slug
organizationSchema.index({ slug: 1 }, { unique: true });

module.exports = mongoose.model('Organization', organizationSchema);
