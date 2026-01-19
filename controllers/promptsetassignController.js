// controllers/promptsetassignController.js
const mongoose = require('mongoose');

const GroupMember = require('../models/member_models/group_member');
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const PromptSet = require('../models/unit_models/promptset');

const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');

const ObjectId = mongoose.Types.ObjectId;

/** Normalize incoming member ids from array and/or CSV mirror */
function normalizeAssignedIds(primary, fallback) {
  // Collect from BOTH sources, not either-or
  const pieces = [];

  // Primary (assignedMemberIds[]) may be array or single string
  if (Array.isArray(primary)) {
    pieces.push(...primary);
  } else if (typeof primary === 'string' && primary.trim()) {
    pieces.push(primary);
  }

  // Fallback CSV mirror (assignedMemberIds) may be array or CSV string
  if (Array.isArray(fallback)) {
    pieces.push(...fallback);
  } else if (typeof fallback === 'string' && fallback.trim()) {
    // may be comma-separated ids
    pieces.push(...fallback.split(','));
  }

  // Clean + dedupe
  const strings = [...new Set(pieces.map(s => String(s).trim()).filter(Boolean))];

  // Validate 24-hex
  const hex24 = strings.filter(x => /^[a-fA-F0-9]{24}$/.test(x));
  if (hex24.length !== strings.length) {
    const bad = strings.filter(x => !/^[a-fA-F0-9]{24}$/.test(x));
    console.warn('⚠️ Ignored invalid member IDs:', bad);
  }

  return {
    objectIds: hex24.map(x => new mongoose.Types.ObjectId(x)),
    stringIds: hex24
  };
}


module.exports = {
  /**
   * POST /promptsetassign/assign
   * Fan-out: one assignment doc per assignee
   * - Enforce limit of 3 UNIQUE sets underway (assignments + registrations)
   * - Skip duplicates of the same prompt set for a member
   * - Initialize PromptSetProgress; do NOT create a PromptSetRegistration (prevents double source)
   */
  assignPromptSet: async (req, res) => {
    try {
      console.log("Assigning prompt set - Full Request Body:", req.body);

      // Normalize assignees (supports assignedMemberIds[] and CSV mirror)
const arrayField = req.body['assignedMemberIds[]'];   // array of ids (hidden inputs)
const csvMirror  = req.body.assignedMemberIdsCsv;     // CSV string we just renamed
      const { objectIds: assignedObjectIds, stringIds: assignedStringIds } =
        normalizeAssignedIds(arrayField, csvMirror);

      // Inputs
      const promptSetIdRaw       = req.body.promptSetId;
      const frequencyRaw         = req.body.frequency;
      const targetCompletionDate = req.body.targetCompletionDate;
      const leaderNotes          = req.body.leaderNotes || '';

      // Auth: your app uses req.user
      const groupLeaderId = req.user && req.user._id ? req.user._id : null;

      // Basic validation
      if (!groupLeaderId) {
        return res.json({ success: false, errorMessage: "You must be logged in as a leader to assign." });
      }
      if (!promptSetIdRaw || !targetCompletionDate) {
        return res.json({ success: false, errorMessage: "Missing required fields. Please fill out all fields." });
      }
      if (!assignedObjectIds.length) {
        return res.json({ success: false, errorMessage: "Please select at least one group member to assign." });
      }

      const frequency = String(frequencyRaw || 'monthly').toLowerCase();

      // Cast ids + date
      const promptSetId = ObjectId.isValid(promptSetIdRaw) ? new ObjectId(promptSetIdRaw) : null;
      if (!promptSetId) {
        return res.json({ success: false, errorMessage: "Prompt set id is invalid." });
      }
      const targetDateISO = new Date(targetCompletionDate);
      if (isNaN(targetDateISO.getTime())) {
        return res.json({ success: false, errorMessage: "Target completion date is invalid." });
      }

      // Validate assignees are real group members
      console.log(" Checking assignedMemberIds in MongoDB:", assignedStringIds);
      const validGroupMembers = await GroupMember.find({ _id: { $in: assignedObjectIds } })
        .select('_id')
        .lean();

      const validObjectIds = validGroupMembers.map(m => m._id);
      if (validObjectIds.length !== assignedObjectIds.length) {
        return res.json({ success: false, errorMessage: "Some selected members are not valid group members." });
      }

      console.log('🧩 Fan-out will create docs for memberIds:', validObjectIds.map(String));

      // Validate prompt set
      const promptSet = await PromptSet.findById(promptSetId).lean();
      if (!promptSet) {
        return res.json({ success: false, errorMessage: "Prompt set not found." });
      }

      // Fan-out per member
      const results = [];

      for (const memberOid of validObjectIds) {
        const memberIdStr = memberOid.toString();

        // ✅ Enforce "max 3 active" and skip duplicates using UNIQUE promptSetIds across assignments + registrations
        const [assignIds, regIds] = await Promise.all([
          AssignPromptSet.find({ assignedMemberIds: memberOid }).distinct('promptSetId'),
          PromptSetRegistration.find({ memberId: memberIdStr }).distinct('promptSetId')
        ]);

        const underway = new Set([...assignIds.map(String), ...regIds.map(String)]);
        const psKey = String(promptSetId);

        // Already has THIS prompt set via assignment or registration
        if (underway.has(psKey)) {
          results.push({ memberId: memberIdStr, skipped: true, reason: 'already_assigned' });
          continue;
        }

        // Already at limit of 3 unique sets underway
        if (underway.size >= 3) {
          results.push({ memberId: memberIdStr, skipped: true, reason: 'limit_exceeded' });
          continue;
        }

        // Double-check: avoid duplicate assignment of same PS to same member
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

        // Ensure per-member progress
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
        } else {
          console.log(`ℹ️ Progress already exists for member ${memberIdStr}, skipping initialization.`);
        }

        // IMPORTANT: Do NOT create a PromptSetRegistration for leader-assigned sets.
        // This prevents duplicates in member dashboards and double-counting toward the limit.
        // If you ever need both, handle dedupe in the dashboard renderer.

        results.push({ memberId: memberIdStr, createdId: assignment._id.toString() });
      }

      // Build success summary
      const createdCount   = results.filter(r => r.createdId).length;
      const skippedLimit   = results.filter(r => r.reason === 'limit_exceeded').length;
      const skippedDupes   = results.filter(r => r.reason === 'already_assigned').length;

      console.log('Fan-out summary:', { createdCount, skippedLimit, skippedDupes });

      // Names for success page
      const membersWithNames = await GroupMember.find({ _id: { $in: validObjectIds } })
        .select('_id name')
        .lean();
      const nameById = Object.fromEntries(membersWithNames.map(m => [m._id.toString(), m.name]));

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

assignSuccess: (req, res) => {
  // pull once; then clear so it doesn’t linger across refreshes
  const s = req.session.lastAssignSummary || {};
  delete req.session.lastAssignSummary;

  const locals = {
    layout: 'unitviewlayout', // ✅ use the unit view layout that the existing success view expects
    title: 'Assignment Successful',

    // Prefer session (authoritative), fall back to query string
    promptSetTitle: s.promptSetTitle || req.query.title || 'Prompt Set',
    assignedNames: Array.isArray(s.assignedNames) ? s.assignedNames : [],
    skippedLimitNames: Array.isArray(s.skippedLimitNames) ? s.skippedLimitNames : [],
    skippedDupesNames: Array.isArray(s.skippedDupesNames) ? s.skippedDupesNames : []
  };

  // ✅ This view actually exists
  return res.render('unit_views/assign_success', locals);
},


  /** GET leader’s assigned prompt sets */
  getAssignedPromptSets: async (req, res) => {
    try {
      const groupLeaderId = req.user && req.user._id ? req.user._id : null;
      if (!groupLeaderId) return res.status(400).json({ message: "User is not authenticated." });

      const assignments = await AssignPromptSet.find({ groupLeaderId })
        .populate('promptSetId', 'promptset_title')
        .populate('assignedMemberIds', 'name')
        .sort({ createdAt: -1 });

      res.status(200).json(assignments);
    } catch (error) {
      console.error('Error fetching assigned prompt sets:', error);
      res.status(500).json({ message: 'Failed to fetch assigned prompt sets.' });
    }
  },

  /** GET current member’s assigned prompt sets */
  getAssignedPromptSetsForMember: async (req, res) => {
    try {
      const memberId = req.user && req.user._id ? req.user._id : null;
      if (!memberId) return res.status(400).json({ message: "User is not authenticated." });

      const memberOid = ObjectId.isValid(memberId) ? new ObjectId(memberId) : null;
      if (!memberOid) return res.status(400).json({ message: "Invalid member id." });

      const assignments = await AssignPromptSet.find({ assignedMemberIds: memberOid })
        .populate('promptSetId', 'promptset_title')
        .populate('groupLeaderId', 'name')
        .sort({ createdAt: -1 });

      res.status(200).json(assignments);
    } catch (error) {
      console.error('Error fetching assigned prompt sets for member:', error);
      res.status(500).json({ message: 'Failed to fetch assigned prompt sets for this member.' });
    }
  },

  /** DELETE one assignment */
  unassignPromptSet: async (req, res) => {
    try {
      const { assignmentId } = req.params;

      const assignment = await AssignPromptSet.findById(assignmentId);
      if (!assignment) {
        return res.status(404).json({ message: 'Assignment not found.' });
      }

      await AssignPromptSet.findByIdAndDelete(assignmentId);
      res.status(200).json({ message: 'Assignment removed successfully.' });
    } catch (error) {
      console.error('Error unassigning prompt set:', error);
      res.status(500).json({ message: 'An error occurred while removing the assignment.' });
    }
  },

  /** DELETE one member’s assignment (fan-out doc) */
unassignPromptSetMember: async (req, res) => {
  try {
    const leaderId = req.user && req.user._id ? req.user._id.toString() : null;
    if (!leaderId) {
      return res.status(401).json({ message: 'Not authenticated.' });
    }

    const { assignmentId, memberId } = req.params;

    if (!ObjectId.isValid(assignmentId) || !ObjectId.isValid(memberId)) {
      return res.status(400).json({ message: 'Invalid assignmentId or memberId.' });
    }

    const assignment = await AssignPromptSet.findById(assignmentId).lean();
    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found.' });
    }

    // ✅ Ensure leader owns this assignment
    if (String(assignment.groupLeaderId) !== String(leaderId)) {
      return res.status(403).json({ message: 'You do not have permission to modify this assignment.' });
    }

    const memberOid = new ObjectId(memberId);

    // ✅ Fan-out guarantee: this doc should only contain one member
    const assignedIds = Array.isArray(assignment.assignedMemberIds) ? assignment.assignedMemberIds.map(String) : [];
    if (!assignedIds.includes(String(memberOid))) {
      return res.status(400).json({ message: 'This assignment is not for the specified member.' });
    }

    const promptSetId = assignment.promptSetId;

    // ✅ Delete the assignment doc
    await AssignPromptSet.findByIdAndDelete(assignmentId);

    // Optional cleanup: remove progress ONLY if no other source keeps it "underway"
    const [stillAssigned, stillRegistered] = await Promise.all([
      AssignPromptSet.exists({ promptSetId, assignedMemberIds: memberOid }),
      PromptSetRegistration.exists({ memberId: memberId, promptSetId })
    ]);

    if (!stillAssigned && !stillRegistered) {
      await PromptSetProgress.deleteOne({ memberId: memberId, promptSetId });
    }

    // If your UI expects redirect instead of JSON, switch to:
    // return res.redirect('/dashboard/leader');

    return res.status(200).json({ message: 'Assignment removed successfully.' });
  } catch (error) {
    console.error('Error unassigning prompt set for member:', error);
    return res.status(500).json({ message: 'An error occurred while removing the assignment.' });
  }
}

};

