// models/member_models/leader.js
const mongoose = require('mongoose');

const leaderSchema = new mongoose.Schema({
  groupName: { type: String, required: [true, 'Group name is required'], trim: true },
  groupLeaderName: { type: String, required: [true, 'Group leader name is required'], trim: true },
  professionalTitle: { type: String, required: [true, 'Professional title is required'], trim: true },
  organization: { type: String, required: [true, 'Organization is required'], trim: true },

  industry: {
    type: String,
    required: [true, 'Industry is required'],
    enum: [
      'Engineering','Architecture','Project Management','Information Technology(IT)',
      'Web Design','Construction','Technology','AI and Robotics',
      'Social Media/Digital Advertising','Community Planning/Landscape Architecture',
      'Land Development','Telecommunications','E-Commerce','Cybersecurity',
      'Fintech','Edtech','Energy and Utilities','Manufacturing','Other'
    ]
  },

  username: { type: String, required: [true, 'Username is required'], unique: true, trim: true },

  groupLeaderEmail: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },

  password: { type: String, required: [true, 'Password is required'], minlength: [6, 'Password must be at least 6 characters'] },

  // Optional; you’ll populate it later if/when you collect/store it in-app
  billingAddress: {
    line1: String,
    line2: String,
    city: String,
    province: String,     // “state” if outside CA; Stripe uses `state` field
    postalCode: String,
    country: { type: String, default: 'CA' } // ISO-2, e.g., CA
  },

  groupSize: { type: Number, required: [true, 'Group size is required'], min: [2, 'Group size must be at least 2 members'], max: [10, 'Group size must not exceed 10 members'] },

  topics: {
    topic1: String,
    topic2: String,
    topic3: String
  },

  profileImage: { type: String, default: '/images/default-avatar.png', trim: true },

  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'GroupMember' }],

  membershipType: { type: String, default: 'leader', enum: ['leader'] },

  registration_code: { type: String, required: [true, 'Registration code is required'], unique: true, trim: true },

  paymentStatus: { type: String, enum: ['pending', 'paid'], default: 'pending' },

  createdAt: { type: Date, default: Date.now },

  // ⬇️ accessLevel removed (redundant for leaders)

  isActive: { type: Boolean, default: true },

  stripeCustomerId: String,
  stripeSubscriptionId: String,

  subscriptionStatus: { type: String, enum: ['active', 'cancelled', 'pending'], default: 'pending' },

  emailPreferenceLevel: { type: Number, enum: [1, 2, 3], default: 1 },
  emailPreferencesUpdatedAt: Date,

  mfa: {
    enabled: { type: Boolean, default: false },
    method: { type: String, enum: ['totp'], default: undefined },
    // encrypted TOTP material
    secretEnc: String,
    secretIv: String,
    secretTag: String,
    recoveryCodes: [{ type: String }],
    updatedAt: Date
  }
}, {
  timestamps: true,
  strict: true // unknown fields discarded
});

module.exports = mongoose.model('Leader', leaderSchema);





