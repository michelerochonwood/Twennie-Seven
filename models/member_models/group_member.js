const mongoose = require('mongoose');

const mfaSchema = new mongoose.Schema({
  enabled: { type: Boolean, default: false },
  method: { type: String, enum: ['totp'], default: undefined },
  // Encrypted at rest (AES-256-GCM). Never store raw.
  secretEnc: { type: String },
  secretIv: { type: String },
  secretTag: { type: String },
  recoveryCodes: [{ type: String }], // bcrypt-hashed codes
  updatedAt: { type: Date }
}, { _id: false });

const groupMemberSchema = new mongoose.Schema({
  // Relationship to the leader who owns the group
  leader: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Leader',
    required: [true, 'Leader ID is required'],
    index: true
  },

  // The display name for the group they joined (works even if you later add multiple groups per leader)
  groupName: {
    type: String,
    required: [true, 'Group name is required'],
    trim: true
  },

  // Org link (copied from leader at creation time). Null allowed for anonymous/opt-out.
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    default: null,
    index: true
  },

  // Optional cache for display/search; keep in sync if you set it.
  organizationName: {
    type: String,
    trim: true,
    maxlength: 120,
    default: ''
  },

  name: {
    type: String,
    required: [true, 'Member name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },

  membershipType: {
    type: String,
    default: 'group_member',
    enum: ['group_member']
  },
  accessLevel: {
    type: String,
    default: 'group_member',
    enum: ['group_member']
  },

  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },

  // Email preferences
  emailPreferenceLevel: {
    type: Number,
    enum: [1, 2, 3],
    default: 1
  },
  emailPreferencesUpdatedAt: { type: Date },

  googleId: { type: String, unique: true, sparse: true },
avatar: { type: String, trim: true },


termsAccepted: {
  type: Boolean,
  default: false,
},
termsAcceptedAt: {
  type: Date,
},
termsVersion: {
  type: String,
  default: "v1",
},
  // MFA
  mfa: mfaSchema
}, {
  timestamps: true
});

// Helpful indexes for reporting
groupMemberSchema.index({ organization: 1, isActive: 1 });
groupMemberSchema.index({ leader: 1, isActive: 1 });

module.exports = mongoose.model('GroupMember', groupMemberSchema);
