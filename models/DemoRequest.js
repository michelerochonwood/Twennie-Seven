const mongoose = require('mongoose');

const demoRequestSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    },

    organization: {
      type: String,
      trim: true
    },

    jobTitle: {
      type: String,
      trim: true
    },

    teamSize: {
      type: String,
      trim: true
    },

    message: {
      type: String,
      trim: true
    },

    status: {
      type: String,
      enum: ['new', 'scheduled', 'completed'],
      default: 'new',
      index: true
    },

    scheduledAt: {
      type: Date,
      default: null
    },

    completedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model(
  'DemoRequest',
  demoRequestSchema
);