// controllers/notesController.js
const mongoose = require('mongoose');
const Note = require('../models/notes/notes');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const GroupMember = require('../models/member_models/group_member');
const Leader = require('../models/member_models/leader');
const Tag = require('../models/tag');

// 1️⃣ CREATE / UPSERT NOTE (Submission Form Handler)
exports.createNote = async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id; // normalized by app.js
    if (!userId) return res.status(401).send('Unauthorized: Please log in.');

    const {
      unitId,
      unitType,              // we now pass 'article' from the view; optional but useful
      main_topic,            // may be provided by the form
      secondary_topic,       // may be provided by the form
      note_content
    } = req.body;

    if (!unitId) return res.status(400).send('Missing unitId.');

    // Ensure only group members or leaders can submit
    const [isGroupMember, isLeader] = await Promise.all([
      GroupMember.findById(userId).select('_id'),
      Leader.findById(userId).select('_id')
    ]);
    if (!isGroupMember && !isLeader) {
      return res.status(403).send('Unauthorized: Only group members and leaders can submit notes.');
    }

    // Resolve the unit to derive topics if not provided in the form
    let unit = null;
    if (!main_topic || !secondary_topic) {
      unit =
        (await Article.findById(unitId)) ||
        (await Video.findById(unitId)) ||
        (await Interview.findById(unitId)) ||
        (await Exercise.findById(unitId)) ||
        (await Template.findById(unitId));

      if (!unit) return res.status(404).send('Unit not found.');
    }

    const effectiveMainTopic = main_topic ?? unit?.main_topic ?? null;
    const effectiveSecondary = secondary_topic ?? unit?.secondary_topic ?? null; // your schema names vary slightly; keep as-is

    // Upsert the note so we don't create duplicates per (member, unit)
    await Note.findOneAndUpdate(
      { unitID: unitId, memberID: userId },
      {
        $set: {
          unitType: unitType || undefined,
          main_topic: effectiveMainTopic,
          secondary_topic: effectiveSecondary,
          note_content: (note_content || '').trim(),
          updatedAt: new Date()
        }
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // ✅ Mark the corresponding leader-assigned tag as completed for this member+unit
    await Tag.updateMany(
      {
        'assignedTo.member': new mongoose.Types.ObjectId(userId),
        'associatedUnits.item': new mongoose.Types.ObjectId(unitId)
        // If you want to match by type too:
        // 'associatedUnits.unitType': unitType
      },
      {
        $set: { 'assignedTo.$[ass].completedAt': new Date() }
      },
      {
        arrayFilters: [{ 'ass.member': new mongoose.Types.ObjectId(userId) }]
      }
    );

    const dashboardLink = isGroupMember ? '/dashboard/groupmember' : '/dashboard/leader';
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

    // Get all group members under this leader (consistent with rest of app: groupId → leader._id)
    const groupMembers = await GroupMember.find({ groupId: leaderId }).select('_id');
    const groupMemberIds = groupMembers.map(m => m._id);

    // Fetch notes submitted by these group members
    const notes = await Note.find({ memberID: { $in: groupMemberIds } })
      .populate('unitID', 'article_title video_title interview_title exercise_title template_title')
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
      .populate('unitID', 'article_title video_title interview_title exercise_title template_title')
      .sort({ createdAt: -1 });

    return res.render('group_member_notes_view', { layout: 'memberlayout', notes });

  } catch (error) {
    console.error('❌ Error fetching notes for group member:', error);
    return res.status(500).send('Error retrieving notes.');
  }
};

