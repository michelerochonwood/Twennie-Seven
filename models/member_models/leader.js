// models/member_models/leader.js
const mongoose = require('mongoose');

const billingAddressSchema = new mongoose.Schema({
  line1: { type: String, trim: true },
  line2: { type: String, trim: true },
  city:  { type: String, trim: true },
  province: { type: String, trim: true }, // use `state` if outside Canada
  postalCode: { type: String, trim: true },
  country: { type: String, default: 'CA', trim: true }
}, { _id: false });

const mfaSchema = new mongoose.Schema({
  enabled:   { type: Boolean, default: false },
  method:    { type: String, enum: ['totp'], default: undefined },
  // Encrypted at rest (AES-256-GCM). Never store raw.
  secretEnc: { type: String },  // base64 ciphertext
  secretIv:  { type: String },  // base64 IV
  secretTag: { type: String },  // base64 auth tag
  recoveryCodes: [{ type: String }], // bcrypt-hashed codes
  updatedAt: { type: Date }
}, { _id: false });

const leaderSchema = new mongoose.Schema({
  groupName: {
    type: String,
    required: [true, 'Group name is required'],
    trim: true
  },
  groupLeaderName: {
    type: String,
    required: [true, 'Group leader name is required'],
    trim: true
  },
  professionalTitle: {
    type: String,
    required: [true, 'Professional title is required'],
    trim: true
  },
organization: {
  type: mongoose.Schema.Types.ObjectId,
  ref: 'Organization',
  default: null
},

organizationOptOut: {
  type: Boolean,
  default: false
},

organizationName: {
  type: String,
  trim: true,
  maxlength: 120,
  default: ''
},

// --- Organization admin ---
isAdmin: {
  type: Boolean,
  default: false
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
    required: [true, 'Username is required'],
    unique: true, // creates a unique index
    trim: true
  },
  groupLeaderEmail: {
    type: String,
    required: [true, 'Email is required'],
    unique: true, // creates a unique index
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },

  billingAddress: billingAddressSchema,

  groupSize: {
    type: Number,
    required: [true, 'Group size is required'],
    min: [2, 'Group size must be at least 2 members'],
    max: [10, 'Group size must not exceed 10 members']
  },

  topics: {
    topic1: { type: String, trim: true },
    topic2: { type: String, trim: true },
    topic3: { type: String, trim: true }
  },

  profileImage: {
    type: String,
    default: '/images/default-avatar.png',
    trim: true
  },

  members: [
    { type: mongoose.Schema.Types.ObjectId, ref: 'GroupMember' }
  ],

  membershipType: {
    type: String,
    default: 'leader',
    enum: ['leader']
  },

  registration_code: {
    type: String,
    required: [true, 'Registration code is required'],
    unique: true,
    trim: true
  },

  paymentStatus: {
    type: String,
    enum: ['pending', 'paid'],
    default: 'pending'
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  accessLevel: {
    type: String,
    default: 'leader',
    enum: ['leader']
  },

  isActive: {
    type: Boolean,
    default: true
  },

  // ---------- Stripe / Billing ----------
  stripeCustomerId: { type: String, trim: true },
  stripeSubscriptionId: { type: String, trim: true },

  // Seat-based billing line item (quantity = seats)
  stripeSubscriptionItemId: { type: String, trim: true },

  // Optional: price used for the seat item (handy for upgrades/downgrades)
  stripePriceId: { type: String, trim: true },

  // Cached bookkeeping for UI/audit
  lastSeatQuantity: { type: Number, default: 0 },
  lastSeatSyncAt: { type: Date },

  // Decide how seats are counted (default: active members)
  seatBillingMode: {
    type: String,
    enum: ['active_members', 'max_group_size'],
    default: 'active_members'
  },

  subscriptionStatus: {
    type: String,
    enum: ['active', 'canceled', 'pending'], // US spelling for Stripe parity
    default: 'pending'
  },

  // ---------- Email preferences ----------
  emailPreferenceLevel: {
    type: Number,
    enum: [1, 2, 3], // 1=minimal, 2=product updates, 3=events+promotions
    default: 1
  },
  emailPreferencesUpdatedAt: { type: Date },

  googleId: { type: String, unique: true, sparse: true },
avatar: { type: String, trim: true },

  // ---------- MFA ----------
  mfa: mfaSchema

}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// ---------- Virtuals ----------
// If GroupMember has isActive, bill only active members.
// When members are populated, count only active ones; otherwise fall back to array length.
leaderSchema.virtual('activeMemberCount').get(function () {
  if (Array.isArray(this.members) && this.members.length && typeof this.members[0] === 'object') {
    return this.members.filter(m => m?.isActive !== false).length;
  }
  return Array.isArray(this.members) ? this.members.length : 0;
});

// ---------- Instance Methods ----------
// Decide the authoritative seat quantity for billing.
leaderSchema.methods.getSeatQuantity = function () {
  if (this.seatBillingMode === 'max_group_size') return this.groupSize || 0;
  // default: active members
  return this.activeMemberCount ?? (this.members?.length || 0);
};

// ---------- Indexes ----------
// Helpful to ensure uniqueness at the DB level (unique above defines indexes, this is explicit safety)
leaderSchema.index({ username: 1 }, { unique: true });
leaderSchema.index({ groupLeaderEmail: 1 }, { unique: true });
leaderSchema.index({ registration_code: 1 }, { unique: true });
leaderSchema.index({ organization: 1 });

const Leader = mongoose.model('Leader', leaderSchema);
module.exports = Leader;





