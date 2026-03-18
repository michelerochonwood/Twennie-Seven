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

  badge_name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 60
  },

  purpose: {
    type: String,
    required: true,
  },

  summary: {
    type: String,
    trim: true,
  },

  additional_instructions: {
    type: String,
    trim: true,
  },

  department_requesting: String,

  open_to: {
    type: String,
    required: false,
  },

  timeframe: String,
  estimated_effort_hours: Number,
  job_number: String,
  budget_amount: String,

  task_instructions: [{
    heading: String,
    instructions: [String],
  }],

  deliverables_checklist: [String],

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

  twennie_learning_units: [{
    unit_id: { type: mongoose.Schema.Types.ObjectId, required: true },
    unit_type: {
      type: String,
      enum: ['article', 'video', 'interview', 'promptset', 'exercise', 'template', 'nugget', 'mission'],
      required: true
    }
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
