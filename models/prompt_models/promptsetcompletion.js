const mongoose = require('mongoose');

const PromptSetCompletionSchema = new mongoose.Schema({
    memberId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    memberType: {
        type: String,
        enum: ['member', 'leader', 'group_member'],
        required: true
    },
    promptSetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'PromptSet',
        required: true
    },
    completedAt: {
        type: Date,
        default: Date.now
    },
    earnedBadge: {
        image: { type: String, trim: true },
        name: { type: String, trim: true }
    },
    notes: {
        type: [String], // Stores an array of notes (one for each prompt)
        default: []
    },
    finalNotes: {
        type: String, // Final thoughts after completing the set
        trim: true
    }
}, { timestamps: true });

module.exports = mongoose.model('PromptSetCompletion', PromptSetCompletionSchema);
