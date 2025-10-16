// models/profile_models/member_profile.js
const mongoose = require('mongoose');

const TopicsSchema = new mongoose.Schema(
  {
    topic1: { type: String, required: false },
    topic2: { type: String, required: false },
    topic3: { type: String, required: false }
  },
  { _id: false }
);

const memberProfileSchema = new mongoose.Schema(
  {
    memberId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Member',
      unique: true
    },

    name: {
      type: String,
      required: true,
      trim: true
    },

    professionalTitle: {
      type: String,
      trim: true,
      default: ''
    },

    profileImage: {
      type: String,
      trim: true,
      default: '/images/default-avatar.png'
    },

    biography: {
      type: String,
      maxlength: 1000,
      default: ''
    },

    goals: {
      type: String,
      maxlength: 1000,
      default: ''
    },

    // Optional topics; only persisted if at least one is provided
    topics: {
      type: TopicsSchema,
      required: false,
      default: undefined
    },

    libraryUnits: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'LibraryUnit'
      }
    ],

    completedPromptSets: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Completion'
      }
    ],

    earnedBadges: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Badge'
      }
    ]
  },
  {
    timestamps: true
  }
);

const MemberProfile = mongoose.model('MemberProfile', memberProfileSchema);
module.exports = MemberProfile;
