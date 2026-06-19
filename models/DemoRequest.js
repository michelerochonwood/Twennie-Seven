// models/DemoRequest.js
// models/DemoRequest.js
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
      required: false,
      trim: true
    },

    jobTitle: {
      type: String,
      required: false,
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


  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('DemoRequest', demoRequestSchema);