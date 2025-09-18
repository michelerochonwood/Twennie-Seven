const mongoose = require('mongoose');

const TopicSuggestionSchema = new mongoose.Schema({
  suggestedBy: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'memberType',
    required: true
  },
  memberType: {
    type: String,
    required: true,
    enum: ['Member', 'GroupMember', 'Leader']
  },
  name: { type: String, required: true },
  email: { type: String, required: true },
  groupName: { type: String },
  topicTitle: { type: String, required: true },
  paragraph1: { type: String, required: true },
  paragraph2: { type: String, required: true },
  paragraph3: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
  approved: { type: Boolean, default: false },
  approvalDate: { type: Date },
  expectedLibraryDate: { type: Date }
});


module.exports = mongoose.model('TopicSuggestion', TopicSuggestionSchema);