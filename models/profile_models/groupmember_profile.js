// models/profile_models/groupmember_profile.js
const mongoose = require('mongoose');

const TopicsSchema = new mongoose.Schema(
  {
    topic1: { type: String, required: false },
    topic2: { type: String, required: false },
    topic3: { type: String, required: false }
  },
  { _id: false }
);

const groupMemberProfileSchema = new mongoose.Schema(
  {
    groupMemberId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'GroupMember',
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

    // 🔓 Optional topics: only persisted if at least one is provided
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

const GroupMemberProfile = mongoose.model('GroupMemberProfile', groupMemberProfileSchema);
module.exports = GroupMemberProfile;
