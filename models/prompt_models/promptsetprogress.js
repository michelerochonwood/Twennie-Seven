const mongoose = require('mongoose');

const PromptSetProgressSchema = new mongoose.Schema({
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
    currentPromptIndex: {
        type: Number,
        default: 0
    },
    completedPrompts: {
        type: [Number],
        default: []
    },
    notes: {
        type: [String],
        default: []
    }
}, { timestamps: true });

PromptSetProgressSchema.index({ memberId: 1, promptSetId: 1 }, { unique: true });

module.exports = mongoose.model('PromptSetProgress', PromptSetProgressSchema);
