const mongoose = require('mongoose');

const memberProfileSchema = new mongoose.Schema({
    memberId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'Member', // Links the profile to the member
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
topics: {
  topic1: String,
  topic2: String,
  topic3: String
},
    libraryUnits: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'LibraryUnit' // References units submitted by the member
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

const MemberProfile = mongoose.model('MemberProfile', memberProfileSchema);

module.exports = MemberProfile;
