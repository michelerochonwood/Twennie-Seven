const mongoose = require('mongoose');

const tabSeenSchema = new mongoose.Schema({
  // current count the user has seen for this tab
  count:  { type: Number, default: 0 },
  // last time the user opened this tab
  seenAt: { type: Date,   default: null },

  // --- optional future-proofing ---
  // store the newest item the user had seen (e.g., newest unit's _id)
  cursorId: { type: mongoose.Schema.Types.ObjectId, default: null },
  // or store a date-based cursor (e.g., newest item's createdAt/updatedAt)
  cursorAt: { type: Date, default: null },
}, { _id: false });

const dashboardSeenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  role:   { type: String, enum: ['leader','group_member','member'], required: true, index: true },

  // flexible per-tab subdocs: tabs.get('library'), tabs.get('tagged'), etc.
  tabs: {
    type: Map,
    of: tabSeenSchema,
    default: {}
  },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, {
  minimize: true,
  collection: 'dashboard_seen'
});

// keep updatedAt fresh
dashboardSeenSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Ensure one row per (user, role)
dashboardSeenSchema.index({ userId: 1, role: 1 }, { unique: true });

module.exports = mongoose.models.DashboardSeen || mongoose.model('DashboardSeen', dashboardSeenSchema);
