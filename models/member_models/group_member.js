const mongoose = require('mongoose');

const groupMemberSchema = new mongoose.Schema({
  groupId: {
    type: mongoose.Schema.Types.ObjectId,
    required: [true, 'Group ID is required'],
    ref: 'Leader'
  },
  
  groupName: {
    type: String,
    required: [true, 'Group name is required'],
    trim: true
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
  isVerified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  },

  // --- New fields for account & email preferences ---
  emailPreferenceLevel: {
    type: Number,
    enum: [1, 2, 3],  // 1=minimal, 2=updates, 3=all including promos/events
    default: 1
  },
  emailPreferencesUpdatedAt: {
    type: Date
  },
  mfa: {
  enabled: { type: Boolean, default: false },
  method: { type: String, enum: ['totp'], default: undefined },
  // Encrypted at rest (AES-256-GCM). Never store raw.
  secretEnc: { type: String },       // base64 of ciphertext
  secretIv: { type: String },        // base64 of IV
  secretTag: { type: String },       // base64 of auth tag
  recoveryCodes: [{ type: String }], // bcrypt-hashed codes
  updatedAt: { type: Date }
},

}, {
  timestamps: true
});

const GroupMember = mongoose.model('GroupMember', groupMemberSchema);

module.exports = GroupMember;



