const PromptSetRegistration = require('../models/prompt_models/promptsetregistration');
const PromptSetProgress = require('../models/prompt_models/promptsetprogress');
const PromptSetCompletion = require('../models/prompt_models/promptsetcompletion');
const PromptSet = require('../models/unit_models/promptset');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const Member = require('../models/member_models/member'); // ✅ Added Member model





module.exports = {
    // ✅ Register a user (Leader, Group Member, or Member) for a prompt set
    registerPromptSet: async (req, res) => {

        try {
            const { promptSetId, frequency, targetCompletionDate } = req.body;
            const { id, membershipType } = req.session.user;
    
            console.log("Request body:", req.body);
    
            if (!promptSetId) {
                return res.status(400).json({ message: 'Missing prompt set ID.' });
            }
    
            // ✅ Ensure the user exists
            let user = await Leader.findById(id) || await GroupMember.findById(id) || await Member.findById(id);
            if (!user) {
                return res.status(404).json({ message: 'User not found.' });
            }
    
            // ✅ Check if user already has 3 prompt set registrations
            const existingRegistrations = await PromptSetRegistration.find({ memberId: id }).populate('promptSetId');
            if (existingRegistrations.length >= 3) {
                console.warn(`Member ${id} has too many prompt registrations, redirecting.`);
                return res.render('toomanyregistrations', {
                    layout: 'dashboardlayout',
                    title: 'Too Many Registrations',
                    registeredPromptSets: existingRegistrations.map(reg => ({
                        _id: reg.promptSetId?._id?.toString(),
                        promptSetTitle: reg.promptSetId?.promptset_title,
                        frequency: reg.frequency,
                        targetCompletionDate: reg.targetCompletionDate.toDateString()
                    })),
                    dashboard: membershipType === 'leader' ? '/dashboard/leader' :
                              membershipType === 'group_member' ? '/dashboard/groupmember' :
                              '/dashboard/member'
                });
            }
    
            // ✅ Ensure the prompt set exists
            const promptSet = await PromptSet.findById(promptSetId);
            if (!promptSet) {
                return res.status(404).json({ message: 'Prompt set not found.' });
            }
    
            // ✅ Ensure user hasn't already completed this prompt set
            const existingCompletion = await PromptSetCompletion.findOne({ memberId: id, promptSetId });
            if (existingCompletion) {
                return res.status(400).json({ message: 'You have already completed this prompt set.' });
            }
    
            // Normalize membershipType
            const normalizedMemberType = (membershipType === 'groupmember')
              ? 'group_member'
              : (membershipType || 'member');
    
            // ✅ Register prompt set
            const registration = new PromptSetRegistration({
                memberId: id,
                memberType: normalizedMemberType,
                promptSetId,
                frequency,
                targetCompletionDate
            });
            await registration.save();
    
            // ✅ Create progress with correct indexing
            const progress = new PromptSetProgress({
                memberId: id,
                memberType: normalizedMemberType,
                promptSetId,
                currentPromptIndex: 0,
                completedPrompts: [],
                notes: []
            });
            await progress.save();
    
            // ✅ Determine correct dashboard redirection
            let dashboardPath = '/dashboard';
            if (membershipType === 'leader') {
                dashboardPath = '/dashboard/leader';
            } else if (normalizedMemberType === 'group_member') {
                dashboardPath = '/dashboard/groupmember';
            } else {
                dashboardPath = '/dashboard/member';
            }
    
            console.log(`✅ Successfully registered user ${id} for prompt set ${promptSetId}`);
    
            res.redirect(`/promptsetregistration/promptsetregistersuccess?title=${encodeURIComponent(promptSet.promptset_title)}&frequency=${frequency}&completion_date=${targetCompletionDate}&dashboard=${dashboardPath}`);
    
        } catch (error) {
            console.error('❌ Error registering prompt set:', error);
            res.status(500).json({ message: 'An error occurred. Please try again.' });
        }
    },
    

    // ✅ Fetch all registered prompt sets for a user
    getRegisteredPromptSets: async (req, res) => {

        try {
            const { id } = req.session.user;
            const registrations = await PromptSetRegistration.find({ memberId: id }).populate('promptSetId');

            const formattedRegistrations = registrations.map(reg => ({
                _id: reg.promptSetId?._id,
                promptSetTitle: reg.promptSetId?.promptset_title,
                frequency: reg.frequency,
                targetCompletionDate: reg.targetCompletionDate.toDateString()
            }));

            res.status(200).json(formattedRegistrations);
        } catch (error) {
            console.error('❌ Error fetching registered prompt sets:', error);
            res.status(500).json({ message: 'An error occurred. Please try again.' });
        }
    },

    // ✅ Update progress for a prompt set
    updateProgress: async (req, res) => {

        try {
            const { promptSetId, promptIndex, note } = req.body;
            const { id } = req.session.user;

            const progress = await PromptSetProgress.findOne({ memberId: id, promptSetId });
            if (!progress) {
                return res.status(404).json({ message: 'Progress not found for this prompt set.' });
            }

            if (!progress.completedPrompts.includes(promptIndex)) {
                progress.completedPrompts.push(promptIndex);
            }

            progress.notes[promptIndex] = note;

            const promptSet = await PromptSet.findById(promptSetId);
            if (!promptSet) {
                return res.status(404).json({ message: 'Prompt set not found.' });
            }

            const totalPrompts = 21;
            if (progress.completedPrompts.length >= totalPrompts) {
                await PromptSetCompletion.create({
                    memberId: id,
                    memberType: progress.memberType,
                    promptSetId,
                    completedAt: new Date(),
                    earnedBadge: promptSet.earnedBadge || "Default Badge",
                    notes: progress.notes,
                    finalNotes: req.body.finalNotes || ""
                });

                await PromptSetProgress.deleteOne({ memberId: id, promptSetId });
            } else {
                await progress.save();
            }

            res.status(200).json({ message: 'Progress updated successfully.' });
        } catch (error) {
            console.error('❌ Error updating progress:', error);
            res.status(500).json({ message: 'An error occurred. Please try again.' });
        }
    },

    // ✅ Unregister from a prompt set
    unregisterPromptSet: async (req, res) => {

        try {
            const { registrationId } = req.params;

            const registration = await PromptSetRegistration.findById(registrationId);
            if (!registration) {
                return res.status(404).json({ message: 'Prompt set registration not found.' });
            }

            await PromptSetProgress.deleteOne({
                memberId: registration.memberId,
                promptSetId: registration.promptSetId
            });

            await PromptSetRegistration.findByIdAndDelete(registrationId);

            res.status(200).json({ message: 'Successfully unregistered from the prompt set and progress tracking deleted.' });
        } catch (error) {
            console.error('❌ Error unregistering prompt set:', error);
            res.status(500).json({ message: 'An error occurred. Please try again.' });
        }
    }
};


