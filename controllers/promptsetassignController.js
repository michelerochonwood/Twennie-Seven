const mongoose = require('mongoose');
const GroupMember = require('../models/member_models/group_member'); // Ensure correct model is imported
const AssignPromptSet = require('../models/prompt_models/assignpromptset');
const PromptSet = require('../models/unit_models/promptset');
const express = require('express');
const bodyParser = require('body-parser');
const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');






const router = express.Router();
router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

module.exports = {
    // Assign a prompt set to group members
    assignPromptSet: async (req, res) => {

        try {
            console.log("Assigning prompt set - Full Request Body:", req.body);
    
            // Extract values from request
            const { promptSetId, assignedMemberIds, targetCompletionDate, leaderNotes, frequency } = req.body;
            const { id: groupLeaderId } = req.session.user;

                    // Debugging: Log extracted values
        console.log("🔍 Extracted Values - PromptSetId:", promptSetId);
        console.log("🔍 Extracted Values - Assigned Member IDs:", assignedMemberIds);
        console.log("🔍 Extracted Values - Frequency:", frequency);
        console.log("🔍 Extracted Values - Target Completion Date:", targetCompletionDate);
        console.log("🔍 Extracted Values - Leader Notes:", leaderNotes);
    
            // Validate input
            if (!assignedMemberIds || assignedMemberIds.length === 0) {
                return res.json({ success: false, errorMessage: "Please select at least one group member to assign." });
            }
    
            let assignedIds = Array.isArray(assignedMemberIds) 
                ? assignedMemberIds.map(id => id.toString().trim()) 
                : [assignedMemberIds.toString().trim()];
    
            if (!promptSetId || !targetCompletionDate) {
                return res.json({ success: false, errorMessage: "Missing required fields. Please fill out all fields." });
            }
    
            console.log("Parsed assignedMemberIds:", assignedIds);
            console.log("Target Completion Date:", targetCompletionDate);
    
            // Verify group members exist in MongoDB
            console.log(" Checking assignedMemberIds in MongoDB:", assignedIds);
            const validGroupMembers = await GroupMember.find({ _id: { $in: assignedIds } }).select('_id');
            console.log("Found valid group members:", validGroupMembers.map(m => m._id.toString()));
    
            const validIds = validGroupMembers.map(member => member._id.toString());
    
            if (validIds.length !== assignedIds.length) {
                return res.json({ success: false, errorMessage: "Some selected members are not valid group members." });
            }
    
            console.log("Valid Group Members:", validIds);
    
            // Verify prompt set exists
            const promptSet = await PromptSet.findById(promptSetId);
            if (!promptSet) {
                return res.json({ success: false, errorMessage: "Prompt set not found." });
            }
    
            // Prevent duplicate assignments
            const existingAssignments = await AssignPromptSet.find({
                promptSetId,
                assignedMemberIds: { $in: validIds }
            });
    
            if (existingAssignments.length > 0) {
                return res.json({ success: false, errorMessage: "One or more selected members already have this prompt set assigned." });
            }
    
            // Save new assignment
            const assignment = new AssignPromptSet({
                promptSetId,
                groupLeaderId,
                assignedMemberIds: validIds,
                frequency: frequency ? String(frequency).trim() : "monthly",
                assignDate: new Date(),
                targetCompletionDate,
                leaderNotes
            });
    
            await assignment.save();
            console.log(" Assignment saved:", assignment);


// Ensure all assigned members get their own registration and progress tracking
for (const memberId of validIds) {
    // Check if this member already has progress for this prompt set
    const existingProgress = await PromptSetProgress.findOne({ memberId, promptSetId });

    if (!existingProgress) {
        const progress = new PromptSetProgress({
            memberId,
            memberType: "group_member",
            promptSetId,
            currentPromptIndex: 0,  // ✅ Start at Prompt 0
            completedPrompts: [],
            notes: []
        });

        await progress.save();
        console.log(`✅ Progress initialized at Prompt 0 for member ${memberId}`);
    } else {
        console.log(`ℹ️ Progress already exists for member ${memberId}, skipping initialization.`);
    }

    // Check if this member is already registered before creating a new record
    const existingRegistration = await PromptSetRegistration.findOne({ memberId, promptSetId });

    if (!existingRegistration) {
        const newRegistration = new PromptSetRegistration({
            memberId,
            promptSetId,
            memberType: "group_member",
            frequency,
            targetCompletionDate,
            assignerId: groupLeaderId
        });

        await newRegistration.save();
        console.log(`✅ Registered assigned prompt set for ${memberId}`);
    } else {
        console.log(`ℹ️ Registration already exists for member ${memberId}, skipping duplicate entry.`);
    }
}



// ✅ Store assigned prompt sets in session without overwriting order
req.session.assignedPromptSets = validIds.map(memberId => ({
    memberId,
    promptSetId
}));

// ✅ Assign prompt sets explicitly to A, B, and C to prevent them from shifting in the session
req.session.groupmemberPromptA = assignedIds[0] ? { memberId: assignedIds[0], promptSetId } : null;
req.session.groupmemberPromptB = assignedIds[1] ? { memberId: assignedIds[1], promptSetId } : null;
req.session.groupmemberPromptC = assignedIds[2] ? { memberId: assignedIds[2], promptSetId } : null;


// ✅ Save session before sending JSON response
req.session.save(err => {
    if (err) {
        console.error("Error: Failed to save session after assignment.", err);
        return res.status(500).json({ errorMessage: "Session update failed after assignment." });
    }

    console.log("Session after assignment update:", JSON.stringify(req.session, null, 2));
    console.log("🔍 RAW Request Body:", req.body);
    console.log("🔍 Frequency from Request:", req.body.frequency);
    console.log("🔍 Target Completion Date from Request:", req.body.targetCompletionDate);
    console.log("🔍 Assigned Members:", req.body.assignedMemberIds);


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

            if (!groupLeaderId) {
                return res.status(400).json({ message: "User is not authenticated." });
            }

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

            if (!memberId) {
                return res.status(400).json({ message: "User is not authenticated." });
            }

            const assignments = await AssignPromptSet.find({ assignedMemberIds: memberId })
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

