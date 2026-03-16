const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    slug: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true
    },

    industry: {
      type: String,
      trim: true
    },

    domains: [
      {
        type: String,
        trim: true,
        lowercase: true
      }
    ],

    isActive: {
      type: Boolean,
      default: true
    }
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.Organization ||
  mongoose.model('Organization', organizationSchema);
