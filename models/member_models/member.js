const mongoose = require('mongoose');

const memberSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true
  },
  professionalTitle: {
    type: String,
    required: [true, 'Professional title is required'],
    trim: true
  },
  organization: {
    type: String,
    trim: true
  },
  industry: {
    type: String,
    required: [true, 'Industry is required'],
    enum: [
      'Engineering',
      'Architecture',
      'Project Management',
      'Information Technology(IT)',
      'Web Design',
      'Construction',
      'Technology',
      'AI and Robotics',
      'Social Media/Digital Advertising',
      'Community Planning/Landscape Architecture',
      'Land Development',
      'Telecommunications',
      'E-Commerce',
      'Cybersecurity',
      'Fintech',
      'Edtech',
      'Energy and Utilities',
      'Manufacturing',
      'Other'
    ]
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true // optional, if you want usernames to be case-insensitive
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  topics: {
    topic1: { type: String },
    topic2: { type: String },
    topic3: { type: String }
  },
  profileImage: {
    type: String,
    default: '/images/default-avatar.png',
    trim: true
  },
  accessLevel: {
    type: String,
    required: true,
    enum: [
      'free_individual',
      'contributor_individual',
      'paid_individual'
    ]
  },
  membershipType: {
    type: String,
    default: 'member',
    enum: ['member']
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  resetPasswordToken: {
    type: String,
    default: undefined
  },
  resetPasswordExpires: {
    type: Date,
    default: undefined
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

const Member = mongoose.model('Member', memberSchema);

module.exports = Member;








