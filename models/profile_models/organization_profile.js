const mongoose = require('mongoose');

const organizationProfileSchema = new mongoose.Schema(
  {
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Organization',
      unique: true
    },

    adminLeaderId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Leader'
    },

    logo: {
      public_id: {
        type: String,
        default: null
      },
      url: {
        type: String,
        default: '/images/default-organization-logo.png'
      }
    },

    bannerImage: {
      public_id: {
        type: String,
        default: null
      },
      url: {
        type: String,
        default: null
      }
    },

    shortDescription: {
      type: String,
      trim: true,
      maxlength: 500
    },

    website: {
      type: String,
      trim: true,
      maxlength: 250
    },

    primaryColor: {
      type: String,
      trim: true,
      maxlength: 20
    },

    secondaryColor: {
      type: String,
      trim: true,
      maxlength: 20
    }
  },
  {
    timestamps: true
  }
);

const OrganizationProfile =
  mongoose.models.OrganizationProfile ||
  mongoose.model('OrganizationProfile', organizationProfileSchema);

module.exports = OrganizationProfile;