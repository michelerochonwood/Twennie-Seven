const mongoose = require('mongoose');

const microStudySchema = new mongoose.Schema({
    status: {
        type: String,
        enum: ['in progress', 'submitted for approval', 'approved'],
        required: true,
        default: 'in progress',
    },
    microstudy_title: {
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
            'Proposal Management',
            'Proposal Strategy',
            'Storytelling in Technical Marketing',
            'Client Experience',
            'Social Media, Advertising, and Other Mysteries',
            'Emotional Intelligence',
            'The Pareto Principle or 80/20',
            'Diversity and Inclusion in Consulting',
            'People Before Profit',
            'Non-Technical Roles in Technical Environments',
            'Leadership in Technical Services',
            'The Advantage of Failure',
            'Social Entrepreneurship',
            'Employee Experience',
            'Project Management Software',
            'CRM Platforms',
            'Client Feedback Software',
            'Workplace Culture',
            'Mental Health in Consulting Environments',
            'Remote and Hybrid Work',
            'Four Day Work Week',
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
                'Proposal Management',
                'Proposal Strategy',
                'Storytelling in Technical Marketing',
                'Client Experience',
                'Social Media, Advertising, and Other Mysteries',
                'Emotional Intelligence',
                'The Pareto Principle or 80/20',
                'Diversity and Inclusion in Consulting',
                'People Before Profit',
                'Non-Technical Roles in Technical Environments',
                'Leadership in Technical Services',
                'The Advantage of Failure',
                'Social Entrepreneurship',
                'Employee Experience',
                'Project Management Software',
                'CRM Platforms',
                'Client Feedback Software',
                'Workplace Culture',
                'Mental Health in Consulting Environments',
                'Remote and Hybrid Work',
                'Four Day Work Week',
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
    microstudy_content: {
        type: String,
        required: true,
        minlength: 300, // Ensures sufficient content
    },
    clarify_topic: { type: Boolean, default: false },
    hypothesis: { type: Boolean, default: false },
    new_ideas: { type: Boolean, default: false },
    transformative: { type: Boolean, default: false },
    permission: { type: Boolean, required: true },
    short_summary: {
        type: String,
        required: true,
        maxlength: 300,
    },
    full_summary: {
        type: String,
        required: true,
        maxlength: 600,
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Reference the User model
        required: true,
    },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
});

// Middleware to update `updated_at` on save
microStudySchema.pre('save', function (next) {
    this.updated_at = Date.now();
    next();
});

const MicroStudy = mongoose.model('MicroStudy', microStudySchema);
module.exports = MicroStudy;

