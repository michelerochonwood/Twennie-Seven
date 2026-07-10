const mongoose = require('mongoose');

const topicVisibilitySchema = new mongoose.Schema(
  {
    projectmanagement: {
      type: Boolean,
      default: true
    },

    businessdevelopmentandmarketing: {
      type: Boolean,
      default: true
    },

    proposals: {
      type: Boolean,
      default: true
    },

    peoplemanagement: {
      type: Boolean,
      default: true
    },

    workplaceculture: {
      type: Boolean,
      default: true
    },

    technology: {
      type: Boolean,
      default: true
    },

    ai: {
      type: Boolean,
      default: true
    }
  },
  {
    _id: false
  }
);

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
    },

    topicVisibility: {
      type: topicVisibilitySchema,
      default: () => ({})
    }
  },
  {
    timestamps: true
  }
);

module.exports =
  mongoose.models.Organization ||
  mongoose.model('Organization', organizationSchema);
