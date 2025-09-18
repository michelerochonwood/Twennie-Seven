const mongoose = require('mongoose');

const leaderProfileSchema = new mongoose.Schema({
    leaderId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'Leader', // Links the profile to the leader
        unique: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    professionalTitle: {
        type: String,
        trim: true
    },
    profileImage: {
        type: String,
        default: '/images/default-avatar.png',
        trim: true
    },
    biography: {
        type: String,
        maxlength: 1000
    },
    goals: {
        type: String,
        maxlength: 1000
    },
    groupLeadershipGoals: {
        type: String,
        maxlength: 1000 // ✅ Specific to leaders
    },
    topics: {
        topic1: { type: String, required: true },
        topic2: { type: String, required: true },
        topic3: { type: String, required: true }
    },
    libraryUnits: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'LibraryUnit' // References units submitted by the leader
        }
    ],
    completedPromptSets: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Completion' // References completed prompt sets
        }
    ],
    earnedBadges: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Badge' // References earned badges
        }
    ]
}, {
    timestamps: true
});

const LeaderProfile = mongoose.model('LeaderProfile', leaderProfileSchema);

module.exports = LeaderProfile;
