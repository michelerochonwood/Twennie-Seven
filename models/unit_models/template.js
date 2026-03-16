const mongoose = require('mongoose');
const topics = require('../../config/topics');

// ----- Shared topic enum -----


const FILE_FORMAT_ENUM = ['pdf', 'word', 'excel', 'ppt', 'other'];

const templateSchema = new mongoose.Schema(
  {
    status: {
      type: String,
      enum: ['in progress', 'submitted for approval', 'approved'],
      required: true,
      default: 'in progress',
    },

    visibility: {
      type: String,
      enum: ['team_only', 'organization_only', 'all_members'],
      required: true,
      default: 'all_members',
      index: true,
    },

    template_title: {
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

    // Stored uploads (populated by your uploader/controller)
    documentUploads: [
      {
        filename: { type: String, required: true },
        mimetype: { type: String, required: true },
        url: { type: String, required: true },
      },
    ],

    // Checklist attributes
    clarify_topic: { type: Boolean, default: false },
    produce_deliverables: { type: Boolean, default: false },
    new_ideas: { type: Boolean, default: false },
    engaging: { type: Boolean, default: false },

    // CHANGED: was Boolean, now String with enum (matches radio group)
    file_format: {
      type: String,
      enum: FILE_FORMAT_ENUM,
      required: true,
    },

    // Must be explicitly checked by the contributor
    permission: { type: Boolean, required: true },

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
      id: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    },

    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  },
  {
    minimize: true,
    collection: 'templates',
  }
);

// Update `updated_at` automatically
templateSchema.pre('save', function (next) {
  this.updated_at = Date.now();
  next();
});

const Template =
  mongoose.models.Template || mongoose.model('Template', templateSchema);
module.exports = Template;



