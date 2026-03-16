const mongoose = require('mongoose');
const topics = require('../../config/topics');

const articleSchema = new mongoose.Schema({
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
    default: 'all_members',
  },

  article_title: {
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

  article_body: {
    type: String,
    required: true,
  },

  clarify_topic: {
    type: Boolean,
    default: false,
  },

  produce_deliverables: {
    type: Boolean,
    default: false,
  },

  new_ideas: {
    type: Boolean,
    default: false,
  },

  include_results: {
    type: Boolean,
    default: false,
  },

  permission: {
    type: Boolean,
    required: true,
  },

  short_summary: {
    type: String,
    required: true,
    maxlength: 300,
    trim: true,
  },

  full_summary: {
    type: String,
    required: false,
    maxlength: 600,
    trim: true,
  },

  author: {
    id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
  },

  image: {
    public_id: {
      type: String,
      default: null,
    },
    url: {
      type: String,
      default: '/images/default-article.png',
    },
  },

  tags: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'tag',
    },
  ],

  created_at: {
    type: Date,
    default: Date.now,
  },

  updated_at: {
    type: Date,
    default: Date.now,
  },
});

// Middleware to update updated_at on save
articleSchema.pre('save', function (next) {
  this.updated_at = Date.now();
  next();
});

// Prevent overwriting the model
const Article = mongoose.models.Article || mongoose.model('Article', articleSchema);

module.exports = Article;






