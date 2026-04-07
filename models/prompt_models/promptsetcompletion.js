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
        type: [String],
        default: []
    },
    finalNotes: {
        type: String,
        trim: true
    }
}, { timestamps: true });

// ✅ Allow multiple completions of the same prompt set by the same learner
// ✅ This index is for lookup speed only, NOT uniqueness
PromptSetCompletionSchema.index({ memberId: 1, promptSetId: 1, completedAt: -1 });

module.exports = mongoose.model('PromptSetCompletion', PromptSetCompletionSchema);
