const mongoose = require('mongoose');

// ----- Shared topic enum -----
const TOPIC_ENUM = [
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
  'Candid Communication',
  'Client Interactions',
  'Cross Selling in Multi-Disciplinary Firms',
  'Analytics in Project Management',
  'Business Development Metrics',
  'Using Lean in Project Management',
  'Turning a Project into a Business Development Powerhouse',
  'Program Management',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Storytelling in Technical Marketing',
  'Client Experience',
  'Social Media, Advertising, and Other Mysteries',
  'Pull Marketing',
  'Emotional Intelligence',
  'The Pareto Principle',
  'People Before Profit',
  'Non-Technical Roles in Technical Environments',
  'Leadership in Technical Consulting',
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
  'The Power of Purpose',
  'Team Building in Consulting',
  'AI in Consulting',
  'AI in Project Management',
  'AI in Learning',
        'Tips and Tricks for Proposal Proofreading',
        'When the Workload is Light',
          'The First 10 Days of a Project',
  'Managing Scope So It Doesnt Manage You',
  'Risk Management',
  'Closing a Project Strategically',
  'Rescuing a Project That Has Gone Off the Rails'
];

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
      enum: TOPIC_ENUM,
      index: true,
    },

    secondary_topics: {
      type: [String],
      enum: TOPIC_ENUM,
      validate: {
        validator: function (arr) {
          // allow 0, 1, or 2 secondary topics
          return Array.isArray(arr) ? arr.length <= 2 : true;
        },
        message: 'You can select up to two secondary topics.',
      },
      default: [],
    },

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



