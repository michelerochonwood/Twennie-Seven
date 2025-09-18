const mongoose = require('mongoose');

const cancelledMemberSchema = new mongoose.Schema({
  originalId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  name: String,
  username: String,
  email: String,
  membershipType: String,
  accessLevel: String,
  wasLeader: {
    type: Boolean,
    default: false
  },
  cancelledAt: {
    type: Date,
    default: Date.now
  },
  reason: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
});

const CancelledMember = mongoose.model('CancelledMember', cancelledMemberSchema);

module.exports = CancelledMember;
