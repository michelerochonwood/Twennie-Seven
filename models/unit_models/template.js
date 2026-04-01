const mongoose = require('mongoose');
const topics = require('../../config/topics');

const templateUploadSchema = new mongoose.Schema(
  {
    filename: {
      type: String,
      required: true,
      trim: true,
    },
    mimetype: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    role: {
      type: String,
      enum: ['view', 'working'],
      required: true,
    },
  },
  { _id: false }
);

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

    // Stored uploads:
    // - one required PDF with role: 'view'
    // - one optional editable file with role: 'working'
    documentUploads: {
      type: [templateUploadSchema],
      default: [],
      validate: [
        {
          validator: function (arr) {
            return Array.isArray(arr) && arr.length <= 2;
          },
          message: 'A template may contain at most 2 files: 1 PDF view file and 1 working file.',
        },
        {
          validator: function (arr) {
            if (!Array.isArray(arr)) return false;

            const viewFiles = arr.filter(file => file.role === 'view');
            const workingFiles = arr.filter(file => file.role === 'working');

            return viewFiles.length <= 1 && workingFiles.length <= 1;
          },
          message: 'A template may contain only one view file and one working file.',
        },
        {
          validator: function (arr) {
            if (!Array.isArray(arr)) return false;

            const viewFiles = arr.filter(file => file.role === 'view');

            if (viewFiles.length !== 1) return false;

            const viewFile = viewFiles[0];
            const isPdfMime = viewFile.mimetype === 'application/pdf';
            const isPdfName = /\.pdf$/i.test(viewFile.filename);

            return isPdfMime || isPdfName;
          },
          message: 'A template must include exactly one PDF view file.',
        },
      ],
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

    engaging: {
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
      maxlength: 600,
      trim: true,
    },

    author: {
      id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        index: true,
      },
    },

    created_at: {
      type: Date,
      default: Date.now,
    },

    updated_at: {
      type: Date,
      default: Date.now,
    },
  },
  {
    minimize: true,
    collection: 'templates',
  }
);

templateSchema.pre('save', function (next) {
  this.updated_at = Date.now();
  next();
});

const Template =
  mongoose.models.Template || mongoose.model('Template', templateSchema);

module.exports = Template;



