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
        default: 0 // Starts at the first prompt
    },
    completedPrompts: {
        type: [Number], // Stores indexes of completed prompts
        default: []
    },
    notes: {
        type: [String], // Array to store one note per prompt
        default: []
    }
}, { timestamps: true });

module.exports = mongoose.model('PromptSetProgress', PromptSetProgressSchema);
