const mongoose = require('mongoose');

const missionSchema = new mongoose.Schema({
  status: {
    type: String,
    enum: ['one time mission', 'on-going', 'intermittent'],
    default: 'one time mission',
    required: true,
  },

  visibility: {
    type: String,
    enum: ['team_only', 'organization_only', 'all_members'],
    default: 'organization_only',
    required: true,
  },

  mission_title: {
    type: String,
    required: true,
    trim: true,
  },

  // --- CORE NARRATIVE FIELDS ---
  purpose: {
    type: String,
    required: true,
  },

  why_it_matters: {
    type: String,
    required: true,
  },

  background: {
    type: String,
    required: false,
  },

  // --- DETAILS ---
  department_requesting: String,

  open_to: {
    type: String,
    required: false,
  },

  timeframe: String, // e.g. "8 weeks"
  estimated_effort_hours: Number, // optional conversion to hours
  job_number: String,
  budget_amount: String,

  approvals_required: [{
    role: String,
    name: String,
    email: String,
  }],

  // --- TASK INSTRUCTIONS ---
  task_instructions: [{
    heading: String,        // "Scheduling", "Interview Guide"
    instructions: [String], // bullet list
  }],

  // --- CONTACTS ---
  contacts: [{
    role: String,
    name: String,
    email: String,
    phone: String,
  }],

  // --- CHECKLIST ---
  deliverables_checklist: [String],

  // The mission is in one topic only
  main_topic: {
    type: String,
    default: 'When the Workload is Light',
  },

  // --- CATEGORY CLASSIFICATIONS ---
  category: {
    type: String,
    enum: [
      'learning',
      'research',
      'business_development',
      'internal_improvement',
      'culture_play',
      'client_experience',
      'community',
      'administrative',
      'other'
    ],
    default: 'internal_improvement',
  },

  // --- COMPLETION RECORDS ---
  completions: [{
    member: { type: mongoose.Schema.Types.ObjectId, ref: 'Member' },
    notes: String,
    checklist_completed: [String],
    uploaded_files: [{
      public_id: String,
      url: String
    }],
    completed_at: { type: Date, default: Date.now }
  }],

  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Member',
    required: true,
  },

  assigned_to: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Member',
  }],

  due_date: Date,

  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

missionSchema.pre('save', function (next) {
  this.updated_at = Date.now();
  next();
});

module.exports = mongoose.model('Mission', missionSchema);
