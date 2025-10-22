const mongoose = require('mongoose');
const GroupMember = require('../models/member_models/group_member'); // Ensure correct model is imported
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const PromptSet = require('../models/unit_models/promptset');
const express = require('express');
const bodyParser = require('body-parser');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');





// Make ObjectId available in this module
const ObjectId = mongoose.Types.ObjectId;

/**
 * Accepts:
 *  - ['68f...', '68f...']                      // array (assignedMemberIds[] >1)
 *  - '68f...'                                   // string (assignedMemberIds[] = 1)
 *  - '68f...,68f...,68f...'                     // CSV mirror (assignedMemberIds)
 *  - [] / '' / null                             // empty
 * Returns: { objectIds: ObjectId[], stringIds: string[] }
 */
function normalizeAssignedIds(primary, fallback) {
  let raw = [];

  if (Array.isArray(primary)) raw = primary;
  else if (typeof primary === 'string' && primary.trim()) raw = [primary];
  else if (Array.isArray(fallback)) raw = fallback;
  else if (typeof fallback === 'string' && fallback.trim()) raw = [fallback];

  // Expand single CSV string if needed
  if (raw.length === 1 && typeof raw[0] === 'string' && raw[0].includes(',')) {
    raw = raw[0].split(',');
  }

  // Clean, dedupe, validate 24-hex
  const strings = [...new Set(raw.map(s => String(s).trim()).filter(Boolean))];
  const hex24   = strings.filter(x => /^[a-fA-F0-9]{24}$/.test(x));

  if (hex24.length !== strings.length) {
    const bad = strings.filter(x => !/^[a-fA-F0-9]{24}$/.test(x));
    console.warn('⚠️ Ignored invalid member IDs:', bad);
  }

  // Convert to ObjectId via mongoose.Types.ObjectId
  const objectIds = hex24.map(x => new ObjectId(x));
  return { objectIds, stringIds: hex24 };
}


const router = express.Router();
router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

function normalizeAssignedIds(primary, fallback) {
  let raw = [];

  if (Array.isArray(primary))       raw = primary;
  else if (typeof primary === 'string' && primary.trim()) raw = [primary];
  else if (Array.isArray(fallback)) raw = fallback;
  else if (typeof fallback === 'string' && fallback.trim()) raw = [fallback];

  // Expand single CSV string if needed
  if (raw.length === 1 && typeof raw[0] === 'string' && raw[0].includes(',')) {
    raw = raw[0].split(',');
  }

  // Clean, dedupe, validate
  const strings = [...new Set(raw.map(s => String(s).trim()).filter(Boolean))];
  const hex24   = strings.filter(x => /^[a-fA-F0-9]{24}$/.test(x));

  if (hex24.length !== strings.length) {
    const bad = strings.filter(x => !/^[a-fA-F0-9]{24}$/.test(x));
    console.warn('⚠️ Ignored invalid member IDs:', bad);
  }

  return { objectIds: hex24.map(x => new ObjectId(x)), stringIds: hex24 };
}

module.exports = {
    // Assign a prompt set to group members
 // Assign a prompt set to group members (fan-out: one doc per member)
assignPromptSet: async (req, res) => {
  try {
    console.log("Assigning prompt set - Full Request Body:", req.body);

    // ---- Normalize selected member ids from both fields ----
    const arrayField = req.body['assignedMemberIds[]'];   // string or array
    const csvMirror  = req.body.assignedMemberIds;        // CSV string or array
    const { objectIds: assignedObjectIds, stringIds: assignedStringIds } =
      normalizeAssignedIds(arrayField, csvMirror);

    // ---- Extract other fields ----
    const promptSetIdRaw       = req.body.promptSetId;
    const frequencyRaw         = req.body.frequency;
    const targetCompletionDate = req.body.targetCompletionDate;
    const leaderNotes          = req.body.leaderNotes || '';

    // IMPORTANT: your app uses req.user (not req.session.user)
    const groupLeaderId        = req.user && req.user._id ? req.user._id : null;

    // ---- Validate basics ----
    if (!groupLeaderId) {
      return res.json({ success: false, errorMessage: "You must be logged in as a leader to assign." });
    }
    if (!promptSetIdRaw || !targetCompletionDate) {
      return res.json({ success: false, errorMessage: "Missing required fields. Please fill out all fields." });
    }
    if (!assignedObjectIds.length) {
      return res.json({ success: false, errorMessage: "Please select at least one group member to assign." });
    }

    const frequency = (String(frequencyRaw || 'monthly')).toLowerCase();

    // ---- Cast promptSetId + date ----
    const promptSetId = ObjectId.isValid(promptSetIdRaw) ? new ObjectId(promptSetIdRaw) : null;
    if (!promptSetId) {
      return res.json({ success: false, errorMessage: "Prompt set id is invalid." });
    }
    const targetDateISO = new Date(targetCompletionDate);
    if (isNaN(targetDateISO.getTime())) {
      return res.json({ success: false, errorMessage: "Target completion date is invalid." });
    }

    // ---- Verify group members exist ----
    console.log(" Checking assignedMemberIds in MongoDB:", assignedStringIds);
    const validGroupMembers = await GroupMember.find({ _id: { $in: assignedObjectIds } })
      .select('_id')
      .lean();

    const validObjectIds = validGroupMembers.map(m => m._id);
    if (validObjectIds.length !== assignedObjectIds.length) {
      return res.json({ success: false, errorMessage: "Some selected members are not valid group members." });
    }

    // ---- Verify prompt set exists ----
    const promptSet = await PromptSet.findById(promptSetId).lean();
    if (!promptSet) {
      return res.json({ success: false, errorMessage: "Prompt set not found." });
    }

    // ---- Fan-out creation: one AssignPromptSet per member ----
    const results = [];
    for (const memberOid of validObjectIds) {
      const memberIdStr = memberOid.toString();

      // Enforce "max 3 active" across assignments + registrations
      // (If you later add completion/archive flags, filter them out here.)
      const [activeAssignCount, activeRegCount] = await Promise.all([
        AssignPromptSet.countDocuments({ assignedMemberIds: memberOid }),
        PromptSetRegistration.countDocuments({ memberId: memberIdStr })
      ]);
      if (activeAssignCount + activeRegCount >= 3) {
        results.push({ memberId: memberIdStr, skipped: true, reason: 'limit_exceeded' });
        continue;
      }

      // Prevent duplicate assignment of the SAME prompt set to this member
      const alreadyAssigned = await AssignPromptSet.exists({
        promptSetId,
        assignedMemberIds: memberOid
      });
      if (alreadyAssigned) {
        results.push({ memberId: memberIdStr, skipped: true, reason: 'already_assigned' });
        continue;
      }

      // Create ONE assignment doc for this member (single id array)
      const assignment = await AssignPromptSet.create({
        promptSetId,
        groupLeaderId,
        assignedMemberIds: [memberOid],
        frequency,
        assignDate: new Date(),
        targetCompletionDate: targetDateISO,
        leaderNotes
      });
      console.log(" Assignment saved:", assignment?._id);

      // Ensure per-member progress (start at prompt 0)
      const existingProgress = await PromptSetProgress.findOne({ memberId: memberIdStr, promptSetId }).lean();
      if (!existingProgress) {
        await new PromptSetProgress({
          memberId: memberIdStr,
          memberType: "group_member",
          promptSetId,
          currentPromptIndex: 0,
          completedPrompts: [],
          notes: []
        }).save();
        console.log(`✅ Progress initialized at Prompt 0 for member ${memberIdStr}`);
      }

      // Ensure per-member registration (so it appears in their dashboard flow)
      const existingRegistration = await PromptSetRegistration.findOne({ memberId: memberIdStr, promptSetId }).lean();
      if (!existingRegistration) {
        await new PromptSetRegistration({
          memberId: memberIdStr,
          memberType: "group_member",
          promptSetId,
          frequency,
          targetCompletionDate: targetDateISO,
          leaderNotes: leaderNotes || null
        }).save();
        console.log(`✅ Registered assigned prompt set for ${memberIdStr}`);
      }

      results.push({ memberId: memberIdStr, createdId: assignment._id.toString() });
    }

    // ---- Build response (keep your existing redirect UX) ----
    const createdCount = results.filter(r => r.createdId).length;
    const skippedLimit = results.filter(r => r.reason === 'limit_exceeded').length;
    const skippedDupes = results.filter(r => r.reason === 'already_assigned').length;

    console.log('Fan-out summary:', { createdCount, skippedLimit, skippedDupes });

    const membersWithNames = await GroupMember.find({ _id: { $in: validObjectIds } })
  .select('_id name')
  .lean();
const nameById = Object.fromEntries(membersWithNames.map(m => [m._id.toString(), m.name]));

// Stash a one-time summary in session for the success page
req.session.lastAssignSummary = {
  promptSetTitle: promptSet.promptset_title,
  assignedNames: results
    .filter(r => r.createdId)
    .map(r => nameById[r.memberId])
    .filter(Boolean),
  skippedLimitNames: results
    .filter(r => r.reason === 'limit_exceeded')
    .map(r => nameById[r.memberId])
    .filter(Boolean),
  skippedDupesNames: results
    .filter(r => r.reason === 'already_assigned')
    .map(r => nameById[r.memberId])
    .filter(Boolean),
};

    return res.json({
      success: true,
      createdCount,
      skippedLimit,
      skippedDupes,
      redirectUrl: `/promptsetassign/assignsuccess?title=${encodeURIComponent(promptSet.promptset_title)}&frequency=${encodeURIComponent(frequency)}&completion_date=${encodeURIComponent(targetCompletionDate)}&dashboard=/dashboard/leader`
    });

  } catch (error) {
    console.error("Error assigning prompt set:", error);
    return res.json({ success: false, errorMessage: "An error occurred while assigning the prompt set. Please try again." });
  }
},


    
    
    
    
    // Fetch assigned prompt sets for a leader
  getAssignedPromptSets: async (req, res) => {
    try {
      const { id: groupLeaderId } = req.session.user;
      if (!groupLeaderId) return res.status(400).json({ message: "User is not authenticated." });

      const assignments = await AssignPromptSet.find({ groupLeaderId })
        .populate('promptSetId', 'promptset_title')
        .populate('assignedMemberIds', 'name');

      res.status(200).json(assignments);
    } catch (error) {
      console.error('Error fetching assigned prompt sets:', error);
      res.status(500).json({ message: 'Failed to fetch assigned prompt sets.' });
    }
  },

    // Fetch assigned prompt sets for an individual member
  getAssignedPromptSetsForMember: async (req, res) => {
    try {
      const { id: memberId } = req.session.user;
      if (!memberId) return res.status(400).json({ message: "User is not authenticated." });

      const memberOid = ObjectId.isValid(memberId) ? new ObjectId(memberId) : null;
      if (!memberOid) return res.status(400).json({ message: "Invalid member id." });

      const assignments = await AssignPromptSet.find({ assignedMemberIds: memberOid })
        .populate('promptSetId', 'promptset_title')
        .populate('groupLeaderId', 'name');

      res.status(200).json(assignments);
    } catch (error) {
      console.error('Error fetching assigned prompt sets for member:', error);
      res.status(500).json({ message: 'Failed to fetch assigned prompt sets for this member.' });
    }
  },

    // Remove an assigned prompt set
    unassignPromptSet: async (req, res) => {

        try {
            const { assignmentId } = req.params;

            const assignment = await AssignPromptSet.findById(assignmentId);
            if (!assignment) {
                return res.status(404).json({ message: 'Assignment not found.' });
            }

            // Delete the assignment
            await AssignPromptSet.findByIdAndDelete(assignmentId);

            res.status(200).json({ message: 'Assignment removed successfully.' });

        } catch (error) {
            console.error('Error unassigning prompt set:', error);
            res.status(500).json({ message: 'An error occurred while removing the assignment.' });
        }
    }
};

