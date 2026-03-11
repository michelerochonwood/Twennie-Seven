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
      'Community Planning/Landscape Architecture',
      'Land Development',
      'E-Commerce',
      'Fintech',
      'Edtech',
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
  googleId: { type: String, unique: true, sparse: true },
avatar: { type: String, trim: true },
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

billingAddress: {
  line1: { type: String, trim: true },
  line2: { type: String, trim: true },
  city: { type: String, trim: true },
  province: { type: String, trim: true },
  postalCode: { type: String, trim: true },
  country: { type: String, trim: true, default: 'CA' }
},

// ---------- Stripe / Billing ----------
stripeCustomerId: { type: String, trim: true },
stripeSubscriptionId: { type: String, trim: true },

subscriptionStatus: {
  type: String,
  enum: ['active', 'canceled', 'pending', 'cancel_at_period_end'],
  default: 'pending'
},

paymentStatus: {
  type: String,
  enum: ['pending', 'paid', 'cancelled'],
  default: 'pending'
},

cancelAt: { type: Date },
}, {
  timestamps: true
});

const Member = mongoose.model('Member', memberSchema);

module.exports = Member;








