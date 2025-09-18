const mongoose = require('mongoose');

const groupProfileSchema = new mongoose.Schema({
    groupId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'Leader', // Links the profile to the group leader
        unique: true
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
        type: String,
        required: true,
        trim: true
    },
    groupSize: {
        type: Number,
        required: true,
        min: 2,
        max: 10
    },
    biography: {
        type: String,
        maxlength: 2000 // ✅ Allows a biography up to 2000 characters
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
        { type: mongoose.Schema.Types.ObjectId, ref: 'GroupMember' } // References group members
    ],
    groupImage: {
        type: String,
        default: '/images/default-group.png',
        trim: true
    }
}, {
    timestamps: true
});

const GroupProfile = mongoose.model('GroupProfile', groupProfileSchema);

module.exports = GroupProfile;

