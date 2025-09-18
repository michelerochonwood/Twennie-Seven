const mongoose = require('mongoose');

const PromptSetRegistrationSchema = new mongoose.Schema({
    memberId: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'memberType',
        required: true
    },
    memberType: {
        type: String,
        enum: ['member', 'group_member', 'leader'],
        required: true
    },
    promptSetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'PromptSet',
        required: true
    },
    frequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly'],
        required: true
    },
    targetCompletionDate: {
        type: Date,
        required: true
    },
    leaderNotes: {
        type: String,
        default: null // Optional field for leader instructions when assigned
    },
    registeredAt: {
        type: Date,
        default: Date.now
    }
});

// Ensure a member can only register for up to 3 active prompt sets
PromptSetRegistrationSchema.index({ memberId: 1 }, { unique: false });

module.exports = mongoose.model('PromptSetRegistration', PromptSetRegistrationSchema);