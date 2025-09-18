const mongoose = require('mongoose');

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
    enum: [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
    ],
  },
  secondary_topics: [
    {
      type: String,
      enum: [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
    ],
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
    type: [String],
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






