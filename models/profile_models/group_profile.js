const mongoose = require('mongoose');

const groupProfileSchema = new mongoose.Schema(
  {
    groupId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Leader',
      required: true
      // ❌ remove `unique: true` from here
    },

    groupName: {
      type: String,
      required: true,
      trim: true
    },

    groupLeaderName: {
      type: String,
      required: true,
      trim: true
    },

    organization: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      default: null
    },

    groupSize: {
      type: Number,
      required: true,
      min: 2,
      max: 10
    },

    biography: {
      type: String,
      maxlength: 2000
    },

    groupGoals: {
      type: String,
      maxlength: 1000
    },

    groupTopics: {
      topic1: { type: String, required: true },
      topic2: { type: String, required: true },
      topic3: { type: String, required: true }
    },

    members: [
      { type: mongoose.Schema.Types.ObjectId, ref: 'GroupMember' }
    ],

    groupImage: {
      type: String,
      default: '/images/default-group.png',
      trim: true
    }
  },
  { timestamps: true }
);

/**
 * ✅ ENFORCE: exactly ONE GroupProfile per leader (group)
 */
groupProfileSchema.index({ groupId: 1 }, { unique: true });

const GroupProfile = mongoose.model('GroupProfile', groupProfileSchema);

module.exports = GroupProfile;

