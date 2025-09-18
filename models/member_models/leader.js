const mongoose = require('mongoose');

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
    type: String,
    required: [true, 'Organization is required'],
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
    required: [true, 'Username is required'],
    unique: true,
    trim: true
  },
  groupLeaderEmail: {
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
  billingAddress: {
  line1: { type: String },
  line2: { type: String },
  city: { type: String },
  province: { type: String }, // use `state` if you're not in Canada
  postalCode: { type: String },
  country: { type: String, default: 'CA' } // or 'US' if applicable
},
  groupSize: {
    type: Number,
    required: [true, 'Group size is required'],
    min: [2, 'Group size must be at least 2 members'],
    max: [10, 'Group size must not exceed 10 members']
  },
topics: {
  topic1: {
    type: String
  },
  topic2: {
    type: String
  },
  topic3: {
    type: String
  }
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
  stripeCustomerId: {
    type: String
  },
  stripeSubscriptionId: {
    type: String
  },
  subscriptionStatus: {
    type: String,
    enum: ['active', 'cancelled', 'pending'],
    default: 'pending'
  },
    emailPreferenceLevel: {
    type: Number,
    enum: [1, 2, 3],           // 1=minimal, 2=product updates, 3=events+promotions
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
  timestamps: true // ✅ Properly placed as the second argument
  
});



const Leader = mongoose.model('Leader', leaderSchema);

module.exports = Leader;




