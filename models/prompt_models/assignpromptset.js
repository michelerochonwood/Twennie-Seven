const mongoose = require('mongoose');

const AssignPromptSetSchema = new mongoose.Schema({
    promptSetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'PromptSet',
        required: true
    },
    groupLeaderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Leader',
        required: true
    },
    assignedMemberIds: {
        type: [mongoose.Schema.Types.ObjectId], // Can be a single or multiple members
        ref: 'Member',
        required: true
    },
    assignDate: {
        type: Date,
        default: Date.now // When the prompt set was assigned
    },
    targetCompletionDate: {
        type: Date,
        required: true // When the group members should complete it
    },
    frequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly', 'quarterly'], // Accepted values
        required: true // Frequency is now a required field
    },
    leaderNotes: {
        type: String,
        trim: true // Additional notes from the leader
    }
}, { timestamps: true });

module.exports = mongoose.model('AssignPromptSet', AssignPromptSetSchema);


