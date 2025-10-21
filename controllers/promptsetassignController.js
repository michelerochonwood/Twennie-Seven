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
 assignPromptSet: async (req, res) => {
    try {
      console.log("Assigning prompt set - Full Request Body:", req.body);

      // Read both possible field names coming from the view
      const arrayField = req.body['assignedMemberIds[]'];   // may be string or array
      const csvMirror  = req.body.assignedMemberIds;        // may be CSV string or array

      // Normalize to clean arrays
      const { objectIds: assignedObjectIds, stringIds: assignedStringIds } =
        normalizeAssignedIds(arrayField, csvMirror);

      // Extract other fields
      const promptSetIdRaw       = req.body.promptSetId;
      const frequencyRaw         = req.body.frequency;
      const targetCompletionDate = req.body.targetCompletionDate;
      const leaderNotes          = req.body.leaderNotes || '';
      const groupLeaderId        = req.session.user?.id;

      // Debugging
      console.log("🔍 Extracted Values - PromptSetId:", promptSetIdRaw);
      console.log("🔍 Extracted Values - Assigned Member IDs (raw):", arrayField || csvMirror);
      console.log("🔍 Normalized IDs (strings):", assignedStringIds);
      console.log("🔍 Frequency:", frequencyRaw);
      console.log("🔍 Target Completion Date:", targetCompletionDate);
      console.log("🔍 Leader Notes:", leaderNotes);

      // Validate input
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

      // Cast promptSetId explicitly
      const promptSetId = ObjectId.isValid(promptSetIdRaw) ? new ObjectId(promptSetIdRaw) : null;
      if (!promptSetId) {
        return res.json({ success: false, errorMessage: "Prompt set id is invalid." });
      }

      // Parse date once
      const targetDateISO = new Date(targetCompletionDate);
      if (isNaN(targetDateISO.getTime())) {
        return res.json({ success: false, errorMessage: "Target completion date is invalid." });
      }

      // Verify group members exist
      console.log(" Checking assignedMemberIds in MongoDB:", assignedStringIds);
      const validGroupMembers = await GroupMember.find({ _id: { $in: assignedObjectIds } })
        .select('_id')
        .lean();

      const validObjectIds = validGroupMembers.map(m => m._id);
      const validStrings   = validObjectIds.map(id => id.toString());

      console.log("Found valid group members:", validStrings);

      if (validObjectIds.length !== assignedObjectIds.length) {
        return res.json({ success: false, errorMessage: "Some selected members are not valid group members." });
      }

      // Verify prompt set exists
      const promptSet = await PromptSet.findById(promptSetId).lean();
      if (!promptSet) {
        return res.json({ success: false, errorMessage: "Prompt set not found." });
      }

      // Prevent duplicate assignments
      const existingAssignments = await AssignPromptSet.find({
        promptSetId,
        assignedMemberIds: { $in: validObjectIds }
      }).lean();

      if (existingAssignments.length > 0) {
        return res.json({ success: false, errorMessage: "One or more selected members already have this prompt set assigned." });
      }

      // Save new assignment (store ObjectIds)
      const assignment = new AssignPromptSet({
        promptSetId,
        groupLeaderId,
        assignedMemberIds: validObjectIds,  // store as ObjectIds
        frequency,
        assignDate: new Date(),
        targetCompletionDate: targetDateISO,
        leaderNotes
      });

      await assignment.save();
      console.log(" Assignment saved:", assignment);

      // Ensure per-member registration + progress
      for (const oid of validObjectIds) {
        const memberIdStr = oid.toString();

        // Progress (start at prompt 0)
        const existingProgress = await PromptSetProgress.findOne({ memberId: memberIdStr, promptSetId }).lean();
        if (!existingProgress) {
          const progress = new PromptSetProgress({
            memberId: memberIdStr,
            memberType: "group_member",
            promptSetId,
            currentPromptIndex: 0,
            completedPrompts: [],
            notes: []
          });
          await progress.save();
          console.log(`✅ Progress initialized at Prompt 0 for member ${memberIdStr}`);
        } else {
          console.log(`ℹ️ Progress already exists for member ${memberIdStr}, skipping initialization.`);
        }

        // Registration
        const existingRegistration = await PromptSetRegistration.findOne({ memberId: memberIdStr, promptSetId }).lean();
        if (!existingRegistration) {
          const newRegistration = new PromptSetRegistration({
            memberId: memberIdStr,
            promptSetId,
            memberType: "group_member",
            frequency,
            targetCompletionDate: targetDateISO,
            assignerId: groupLeaderId
          });
          await newRegistration.save();
          console.log(`✅ Registered assigned prompt set for ${memberIdStr}`);
        } else {
          console.log(`ℹ️ Registration already exists for member ${memberIdStr}, skipping duplicate entry.`);
        }
      }

      // Session bookkeeping (optional, unchanged)
      req.session.assignedPromptSets = validStrings.map(memberId => ({ memberId, promptSetId: promptSetIdRaw }));
      req.session.groupmemberPromptA = validStrings[0] ? { memberId: validStrings[0], promptSetId: promptSetIdRaw } : null;
      req.session.groupmemberPromptB = validStrings[1] ? { memberId: validStrings[1], promptSetId: promptSetIdRaw } : null;
      req.session.groupmemberPromptC = validStrings[2] ? { memberId: validStrings[2], promptSetId: promptSetIdRaw } : null;

      // Save session and respond
      req.session.save(err => {
        if (err) {
          console.error("Error: Failed to save session after assignment.", err);
          return res.status(500).json({ success: false, errorMessage: "Session update failed after assignment." });
        }

        console.log("Session after assignment update:", JSON.stringify(req.session, null, 2));
        res.json({
          success: true,
          redirectUrl: `/promptsetassign/assignsuccess?title=${encodeURIComponent(promptSet.promptset_title)}&frequency=${encodeURIComponent(frequency)}&completion_date=${encodeURIComponent(targetCompletionDate)}&dashboard=/dashboard/leader`
        });
      });

    } catch (error) {
      console.error("Error assigning prompt set:", error);
      res.json({ success: false, errorMessage: "An error occurred while assigning the prompt set. Please try again." });
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

