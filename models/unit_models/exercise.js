const mongoose = require('mongoose');
const topics = require('../../config/topics');

const exerciseSchema = new mongoose.Schema({
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
  exercise_title: {
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
  file_format: {
    type: String,
    required: true,
    enum: [
      'MS Word',
      'MS Excel',
      'MS PowerPoint',
      'PDF',
      'Mural',
      'Another format - please contact Twennie administrators',
    ],
  },
document_uploads: {
  type: [
    {
      url: {
        type: String,
        required: true,
        trim: true,
      },
      filename: {
        type: String,
        required: true,
        trim: true,
      },
    }
  ],
  validate: [arr => arr.length <= 3, 'You may upload up to 3 documents only.'],
},
  time_required: {
    type: String,
    enum: ['15 mins', '30 mins', '1 hour', '1.5 hours'],
    required: true,
  },
  clarify_topic: { type: Boolean, default: false },
  topics_and_enlightenment: { type: Boolean, default: false },
  challenge: { type: Boolean, default: false },
  instructions: { type: Boolean, default: false },
  time: { type: Boolean, default: false },
  permission: { type: Boolean, required: true },
  short_summary: {
    type: String,
    required: true,
    maxlength: 300,
  },
full_summary: {
  type: String,
  required: false, // now optional
  maxlength: 600,
  trim: true,
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

exerciseSchema.pre('save', function (next) {
  this.updated_at = Date.now();
  next();
});

const Exercise = mongoose.model('Exercise', exerciseSchema);
module.exports = Exercise;






