const mongoose = require('mongoose');

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
        enum: [
  'AI in Consulting',
  'AI in Learning',
  'AI in Project Management',
  'Analytics in Project Management',
  'Business Development in Technical Services',
  'Business Development Metrics',
  'Candid Communication',
  'Career Development in Technical Services',
  'Client Experience',
  'Client Feedback Software',
  'Client Interactions',
  'Closing a Project Strategically',
  'Conducting Color Reviews of Proposals',
  'Cross Selling in Multi-Disciplinary Firms',
  'CRM Platforms',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
  'Non-Technical Roles in Technical Environments',
  'People Before Profit',
  'Program Management',
  'Project Management',
  'Project Management Software',
  'Proposal Management',
  'Proposal Strategy',
  'Pull Marketing',
  'Pursuing the Right Projects for Your Firm and Your Team',
  'Remote and Hybrid Work',
  'Rescuing a Project That Has Gone Off the Rails',
  'Risk Management',
  'Social Entrepreneurship',
  'Social Media, Advertising, and Other Mysteries',
  'Soft Skills in Technical Environments',
  'Storytelling in Technical Marketing',
  'Team Building in Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
        ],
    },
    secondary_topics: [
        {
            type: String,
            enum: [
  'AI in Consulting',
  'AI in Learning',
  'AI in Project Management',
  'Analytics in Project Management',
  'Business Development in Technical Services',
  'Business Development Metrics',
  'Candid Communication',
  'Career Development in Technical Services',
  'Client Experience',
  'Client Feedback Software',
  'Client Interactions',
  'Closing a Project Strategically',
  'Conducting Color Reviews of Proposals',
  'Cross Selling in Multi-Disciplinary Firms',
  'CRM Platforms',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
  'Non-Technical Roles in Technical Environments',
  'People Before Profit',
  'Program Management',
  'Project Management',
  'Project Management Software',
  'Proposal Management',
  'Proposal Strategy',
  'Pull Marketing',
  'Pursuing the Right Projects for Your Firm and Your Team',
  'Remote and Hybrid Work',
  'Rescuing a Project That Has Gone Off the Rails',
  'Risk Management',
  'Social Entrepreneurship',
  'Social Media, Advertising, and Other Mysteries',
  'Soft Skills in Technical Environments',
  'Storytelling in Technical Marketing',
  'Team Building in Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
            ],
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





