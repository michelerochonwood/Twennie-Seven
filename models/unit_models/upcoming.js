// models/library_models/upcoming_unit.js
const mongoose = require('mongoose');

const TOPIC_ENUM = [/* ... keep your topic list ... */];

const UNIT_TYPE = [
  'article','video','interview','exercise','template',
  'promptset','microcourse','microstudy','peercoaching'
];

const UPCOMING_STATUS = ['in production','released','cancelled'];

const upcomingUnitSchema = new mongoose.Schema({
  status: { type: String, enum: UPCOMING_STATUS, required: true, default: 'in production' },
  visibility: { type: String, enum: ['team_only','organization_only','all_members'], required: true, default: 'all_members', index: true },
  unit_type: { type: String, enum: UNIT_TYPE, required: true },
  title: { type: String, required: true, trim: true },

  main_topic: { type: String, enum: TOPIC_ENUM, required: true, index: true },
  secondary_topics: [{ type: String, enum: TOPIC_ENUM }],
  sub_topic: { type: String, trim: true },

  teaser: { type: String, maxlength: 300, trim: true },
  long_teaser: { type: String, maxlength: 1000, trim: true },

  image: {
    public_id: { type: String, default: null },
    url: { type: String, default: '/images/default-upcoming.png' },
    alt: { type: String, trim: true, default: '' },
  },

  projected_release_at: { type: Date, required: true, index: true },

  tags: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Tag' }],

  interested_members: [{ type: mongoose.Schema.Types.ObjectId, index: true }],

  published_unit_ref: {
    model: { type: String, enum: UNIT_TYPE.concat(['other']) },
    id: { type: mongoose.Schema.Types.ObjectId, default: null },
  },

  is_featured: { type: Boolean, default: false },
  priority: { type: Number, default: 0 },

  // ownership (used for "my library units")
  createdBy: { type: mongoose.Schema.Types.ObjectId, refPath: 'createdByModel', index: true },
  createdByModel: { type: String, enum: ['leader','group_member','member'], default: null },

  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
},
{
  minimize: true,
  collection: 'upcomingunits',   // 👈 point back to your existing collection
});

upcomingUnitSchema.pre('save', function(next){
  this.updated_at = Date.now();
  next();
});

upcomingUnitSchema.index({ status: 1, projected_release_at: 1 });
upcomingUnitSchema.index({ main_topic: 1, unit_type: 1 });
upcomingUnitSchema.index({ is_featured: 1, priority: -1, projected_release_at: 1 });

upcomingUnitSchema.virtual('interest_count').get(function(){
  return (this.interested_members || []).length;
});

// 👇 keep the original model name so Mongoose doesn't make a new collection
module.exports = mongoose.models.UpcomingUnit || mongoose.model('UpcomingUnit', upcomingUnitSchema);

