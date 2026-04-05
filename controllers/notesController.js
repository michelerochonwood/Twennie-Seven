// controllers/notesController.js
const mongoose = require('mongoose');
const Note = require('../models/notes/notes');

const Article   = require('../models/unit_models/article');
const Video     = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const Exercise  = require('../models/unit_models/exercise');
const Template  = require('../models/unit_models/template');
const Mission   = require('../models/unit_models/mission');
const Member      = require('../models/member_models/member');

const GroupMember = require('../models/member_models/group_member');
const Leader      = require('../models/member_models/leader');

const Tag = require('../models/tag');
const Nugget = require('../models/unit_models/nugget');

/**
 * Resolve unit by id across known unit collections.
 * Returns { unit, type } where type ∈ 'article' | 'video' | 'interview' | 'exercise' | 'template' | 'mission' | null
 */
async function resolveUnitAndType(unitId) {
  const [a, v, i, e, t, m, n] = await Promise.all([
    Article.findById(unitId).select('main_topic secondary_topics secondary_topic discipline region').lean(),
    Video.findById(unitId).select('main_topic secondary_topics secondary_topic').lean(),
    Interview.findById(unitId).select('main_topic secondary_topics secondary_topic').lean(),
    Exercise.findById(unitId).select('main_topic secondary_topics secondary_topic').lean(),
    Template.findById(unitId).select('main_topic secondary_topics secondary_topic').lean(),
    Mission.findById(unitId).select('main_topic secondary_topics secondary_topic').lean(),
    Nugget.findById(unitId).select('discipline region').lean()
  ]);

  if (a) return { unit: a, type: 'article' };
  if (v) return { unit: v, type: 'video' };
  if (i) return { unit: i, type: 'interview' };
  if (e) return { unit: e, type: 'exercise' };
  if (t) return { unit: t, type: 'template' };
  if (m) return { unit: m, type: 'mission' };
  if (n) return { unit: n, type: 'nugget' };
  return { unit: null, type: null };
}

// 1️⃣ CREATE / UPSERT NOTE (Submission Form Handler)
// 1️⃣ CREATE / UPSERT NOTE (Submission Form Handler)
exports.createNote = async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id;
    if (!userId) return res.status(401).send('Unauthorized: Please log in.');

    const {
      unitId,
      unitType,
      main_topic,
      secondary_topic,
      note_content
    } = req.body;

    if (!unitId) return res.status(400).send('Missing unitId.');

    // Allow leaders, group members, and individual members
    const [isGroupMember, isLeader, isMember] = await Promise.all([
      GroupMember.exists({ _id: userId }),
      Leader.exists({ _id: userId }),
      Member.exists({ _id: userId })
    ]);

    if (!isGroupMember && !isLeader && !isMember) {
      return res.status(403).send('Unauthorized: Only members, group members, and leaders can submit notes.');
    }

    // Resolve topics/unit type if the form didn't provide them
    let effectiveUnitType   = unitType || null;
    let effectiveMainTopic  = main_topic || null;
    let effectiveSecondary  = secondary_topic || null;

if (!effectiveUnitType || !effectiveMainTopic) {
      const { unit, type } = await resolveUnitAndType(unitId);
      if (!unit) return res.status(404).send('Unit not found.');

      if (!effectiveUnitType)  effectiveUnitType  = type;
      if (!effectiveMainTopic) effectiveMainTopic = unit.main_topic ?? null;

      if (!effectiveSecondary) {
        if (typeof unit.secondary_topic === 'string') {
          effectiveSecondary = unit.secondary_topic;
        } else if (Array.isArray(unit.secondary_topics) && unit.secondary_topics.length) {
          effectiveSecondary = unit.secondary_topics.join(', ');
        } else {
          effectiveSecondary = null;
        }
      }
    }

const content = (note_content || '').trim();

if (effectiveUnitType === 'nugget' || effectiveUnitType === 'mission') {
  // Nuggets and missions keep a running history of notes
  await Note.create({
    unitID: unitId,
    memberID: userId,
    unitType: effectiveUnitType,
    main_topic: effectiveMainTopic,
    secondary_topic: effectiveSecondary,
    note_content: content
  });
} else {
  // Learning units keep one current note per user/unit
  await Note.findOneAndUpdate(
    { unitID: unitId, memberID: userId },
    {
      $set: {
        unitType:        effectiveUnitType || undefined,
        main_topic:      effectiveMainTopic,
        secondary_topic: effectiveSecondary,
        note_content:    content,
        updatedAt:       new Date()
      }
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

    /**
     * Mark corresponding leader assignment as completed for this user + unit.
     * This only matters for users who can actually receive assignments:
     * group members and leaders.
     */
    if (isGroupMember || isLeader) {
      await Tag.updateMany(
        {
          'assignedTo.member': new mongoose.Types.ObjectId(userId),
          associatedUnits: {
            $elemMatch: {
              item: new mongoose.Types.ObjectId(unitId),
              ...(effectiveUnitType ? { unitType: effectiveUnitType } : {})
            }
          }
        },
        {
          $set: { 'assignedTo.$[ass].completedAt': new Date() }
        },
        {
          arrayFilters: [{ 'ass.member': new mongoose.Types.ObjectId(userId) }]
        }
      );
    }

    /**
     * If this note belongs to a mission, mark that mission as completed for this user.
     * This only matters for roles that use missions.
     */
    if (effectiveUnitType === 'mission' && (isGroupMember || isLeader)) {
      const mission = await Mission.findById(unitId);
      if (mission) {
        const alreadyCompleted = Array.isArray(mission.completions)
          ? mission.completions.some(c =>
              c.member && c.member.toString() === userId.toString()
            )
          : false;

        if (!alreadyCompleted) {
          mission.completions = mission.completions || [];
          mission.completions.push({
            member: userId,
            notes: content || undefined,
            completed_at: new Date()
          });
          await mission.save();
        }
      }
    }

    let dashboardLink = '/dashboard/member';
    if (isGroupMember) dashboardLink = '/dashboard/groupmember';
    if (isLeader) dashboardLink = '/dashboard/leader';

    return res.render('unit_views/unitnotessuccess', {
      layout: 'unitviewlayout',
      dashboard: dashboardLink
    });

  } catch (error) {
    console.error('❌ Error submitting note:', error);
    return res.status(500).send('Error saving note.');
  }
};

// 2️⃣ GET NOTES FOR LEADERS (Group Member Notes)
exports.getNotesByLeader = async (req, res) => {
  try {
    const leaderId = req.user?._id || req.user?.id;
    if (!leaderId) return res.status(401).send('Unauthorized: Please log in.');

    // Ensure the requester is a leader
    const leader = await Leader.findById(leaderId).select('_id');
    if (!leader) {
      return res.status(403).send('Unauthorized: Only leaders can view notes.');
    }

    // Get all group members under this leader (groupId = leaderId in your app)
    const groupMembers = await GroupMember.find({ groupId: leaderId }).select('_id');
    const groupMemberIds = groupMembers.map(m => m._id);

    // Fetch notes submitted by these group members
    const notes = await Note.find({ memberID: { $in: groupMemberIds } })
      .populate(
        'unitID',
        'article_title video_title interview_title exercise_title template_title mission_title'
      )
      .sort({ createdAt: -1 });

    return res.render('leader_notes_view', { layout: 'leaderlayout', notes });

  } catch (error) {
    console.error('❌ Error fetching notes for leader:', error);
    return res.status(500).send('Error retrieving notes.');
  }
};

// 3️⃣ GET NOTES FOR GROUP MEMBERS (Their Own Notes)
exports.getNotesByGroupMember = async (req, res) => {
  try {
    const memberId = req.user?._id || req.user?.id;
    if (!memberId) return res.status(401).send('Unauthorized: Please log in.');

    // Ensure the requester is a group member
    const groupMember = await GroupMember.findById(memberId).select('_id');
    if (!groupMember) {
      return res.status(403).send('Unauthorized: Only group members can view their notes.');
    }

    // Fetch all notes submitted by this group member
    const notes = await Note.find({ memberID: memberId })
      .populate(
        'unitID',
        'article_title video_title interview_title exercise_title template_title mission_title'
      )
      .sort({ createdAt: -1 });

    return res.render('group_member_notes_view', { layout: 'memberlayout', notes });

  } catch (error) {
    console.error('❌ Error fetching notes for group member:', error);
    return res.status(500).send('Error retrieving notes.');
  }
};

// 4️⃣ GET NOTES FOR INDIVIDUAL MEMBERS (Their Own Notes)
exports.getNotesByMember = async (req, res) => {
  try {
    const memberId = req.user?._id || req.user?.id;
    if (!memberId) return res.status(401).send('Unauthorized: Please log in.');

    // Ensure the requester is an individual member
    const member = await Member.findById(memberId).select('_id');
    if (!member) {
      return res.status(403).send('Unauthorized: Only individual members can view these notes.');
    }

    const notes = await Note.find({ memberID: memberId })
      .populate(
        'unitID',
        'article_title video_title interview_title exercise_title template_title mission_title'
      )
      .sort({ createdAt: -1 });

    return res.render('member_notes_view', { layout: 'memberlayout', notes });

  } catch (error) {
    console.error('❌ Error fetching notes for individual member:', error);
    return res.status(500).send('Error retrieving notes.');
  }
};



