const mongoose = require('mongoose');
const topics = require('../config/topics');

const videoSchema = new mongoose.Schema({
    status: {
        type: String,
        enum: ['in progress', 'submitted for approval', 'approved'],
        required: true,
        default: 'in progress',
    },
    visibility: {
        type: String,
        required: true,
        enum: ['team_only', 'organization_only', 'all_members'],
        default: 'all_members'
      },
    video_title: {
        type: String,
        required: true,
        trim: true,
    },
  main_topic: {
    type: String,
    required: true,
    enum: topics,
  },

  secondary_topics: [
    {
      type: String,
      enum: topics,
    },
  ],
    sub_topic: {
        type: String,
        trim: true,
    },
    video_content: {
        type: String,
        required: true,
        trim: true,
    },
    clarify_topic: { type: Boolean, default: false },
    produce_deliverables: { type: Boolean, default: false },
    new_ideas: { type: Boolean, default: false },
    engaging: { type: Boolean, default: false },
    permission: { type: Boolean, required: true },
    short_summary: {
        type: String,
        required: true,
        maxlength: 300,
    },
full_summary: {
  type: String,
  required: false, // ⬅️ make it optional
  maxlength: 600,
  trim: true
},
    author: {
        id: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
        },
    },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
});

// Middleware to update updated_at on save
videoSchema.pre('save', function (next) {
    this.updated_at = Date.now();
    next();
});

const Video = mongoose.model('Video', videoSchema);
module.exports = Video;





