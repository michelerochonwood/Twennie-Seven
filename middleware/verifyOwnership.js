// File: middleware/verifyOwnership.js
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member'); // Import GroupMember model

const verifyOwnership = async (req, res, next) => {
    try {
        const { id, membershipType } = req.user || {}; // Use Passport's user object
        const profileId = req.params.id;

        // Check if the user is authenticated
        if (!id || !membershipType) {
            console.warn('User is not authenticated.');
            return res.redirect('/auth/login');
        }

        let user;
        // Fetch the correct user based on membership type
        if (membershipType === 'member') {
            user = await Member.findById(profileId).lean();
        } else if (membershipType === 'leader') {
            user = await Leader.findById(profileId).lean();
        } else if (membershipType === 'group_member') {
            user = await GroupMember.findById(profileId).lean();
        } else {
            console.warn(`Invalid membership type: ${membershipType}`);
            return res.status(403).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Access Denied',
                errorMessage: 'You do not have permission to edit this profile.',
            });
        }

        // Check if the profile exists
        if (!user) {
            console.warn(`Profile not found for ID: ${profileId}`);
            return res.status(404).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Profile Not Found',
                errorMessage: 'Profile not found.',
            });
        }

        // Public profile: Skip ownership checks for member profiles
        if (membershipType === 'member') {
            req.profile = user; // Pass the profile data for rendering
            return next();
        }

        // Private profiles: Ensure the authenticated user owns the profile
        if (user._id.toString() !== id) {
            console.warn('Access denied: User does not own this profile.');
            return res.status(403).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Access Denied',
                errorMessage: 'You do not have permission to edit this profile.',
            });
        }

        // Pass the profile data to the next middleware or route handler
        req.profile = user;
        next();
    } catch (err) {
        console.error('Error verifying ownership:', err.message);
        res.status(500).render('member_form_views/error', {
            layout: 'mainlayout',
            title: 'Error',
            errorMessage: 'An error occurred while verifying profile ownership.',
        });
    }
};


module.exports = verifyOwnership;



