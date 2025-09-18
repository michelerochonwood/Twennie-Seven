const mongoose = require("mongoose");

const ProfileSurveySchema = new mongoose.Schema({
  name: String,
  email: String,
  role: [String],
  wantsProfile: String,
  profileTypes: [String],
  profileComponents: [String],
  visibility: String,
  connect: String,
  notes: String,
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("ProfileSurvey", ProfileSurveySchema);
