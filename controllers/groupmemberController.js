// controllers/groupmemberController.js
const bcrypt = require('bcrypt');

const GroupMember = require("../models/member_models/group_member");
const GroupMemberProfile = require("../models/profile_models/groupmember_profile");
const Leader = require("../models/member_models/leader");
const { validateGroupMemberData } = require("../utils/validateGroupMember");

/**
 * Helper: render standard error page
 */
function renderError(res, message, status = 500) {
  return res.status(status).render('member_form_views/error', {
    layout: 'mainlayout',
    title: 'Error',
    errorMessage: message,
  });
}

/**
 * GET /groupmember/verify
 * Renders the verification page, listing groups and their members (via aggregation)
 */
module.exports.showVerifyMemberForm = async (req, res) => {
  try {
    const csrfToken = req.csrfToken ? req.csrfToken() : null;

    // Join Leaders with their GroupMembers
    const groups = await Leader.aggregate([
      {
        $lookup: {
          from: 'groupmembers',           // collection name for GroupMember
          localField: '_id',
          foreignField: 'groupId',
          as: 'members',
        },
      },
    ]);

    return res.render('member_form_views/verifymember', {
      layout: 'memberformlayout',
      title: 'Verify Group Membership',
      csrfToken,
      groups,
    });
  } catch (err) {
    console.error('Error rendering verify member form:', err.message);
    return renderError(res, 'An error occurred while loading the verification form.');
  }
};

/**
 * POST /groupmember/verify-registration-code
 * Validates a leader’s registration_code and flags the matching group for the UI.
 * Re-renders the same verify page with a highlighted/verified group.
 */
module.exports.verifyRegistrationCode = async (req, res) => {
  try {
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    const { groupId, registration_code } = req.body;

    // Rebuild groups list for display
    const groups = await Leader.aggregate([
      {
        $lookup: {
          from: 'groupmembers',
          localField: '_id',
          foreignField: 'groupId',
          as: 'members'
        }
      }
    ]);

    const leader = await Leader.findById(groupId);

    // Mark which group matched / failed
    groups.forEach(group => {
      const isMatch = group._id.toString() === groupId;
      group.verified = Boolean(isMatch && leader && leader.registration_code === registration_code);
      group.error = Boolean(isMatch && !group.verified);
    });

    return res.status(200).render("member_form_views/verifymember", {
      layout: "memberformlayout",
      title: "Verify Group Membership",
      csrfToken,
      groups,
    });

  } catch (err) {
    console.error("❌ Error verifying registration code:", err.message);
    return renderError(res, "An error occurred while verifying the registration code.");
  }
};

/**
 * (Optional AJAX) POST /groupmember/verify-member
 * If you have a front-end step that checks a name+email combo within a group.
 * Not wired in routes you shared, but keeping it for compatibility.
 */
module.exports.verifyMember = async (req, res) => {
  try {
    const { memberName, memberEmail, groupId } = req.body;

    const groupMember = await GroupMember.findOne({
      groupId,
      name: memberName,
      email: memberEmail,
    });

    if (!groupMember) {
      return res.status(400).json({ valid: false, error: "Member not found in the group." });
    }

    return res.json({
      valid: true,
      member: { name: groupMember.name, email: groupMember.email }
    });
  } catch (err) {
    console.error("❌ Error verifying group member:", err.message);
    return res.status(500).json({ valid: false, error: "Server error during verification." });
  }
};

/**
 * GET /groupmember/complete-registration
 * Renders the completion form for a specific unregistered member.
 * Expects query params: ?groupId=...&email=...
 */
module.exports.showCompleteMemberForm = async (req, res) => {
  try {
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    const { groupId, email } = req.query;

    if (!groupId || !email) {
      return renderError(res, 'Missing groupId or email for completion.', 400);
    }

    const leader = await Leader.findById(groupId).lean();
    if (!leader) {
      return renderError(res, 'Leader/group not found.', 404);
    }

    const member = await GroupMember.findOne({ groupId: leader._id, email }).lean();
    if (!member) {
      return renderError(res, 'No matching group member found for that email.', 404);
    }

    // Render a completion form where user can set username/password, confirm name/email
    return res.render('member_form_views/completemember', {
      layout: 'memberformlayout',
      title: 'Complete Registration',
      csrfToken,
      leader,
      member // contains name & email that we’ll display (usually read-only)
    });
  } catch (err) {
    console.error('Error loading complete registration form:', err.message);
    return renderError(res, 'An error occurred while loading the completion form.');
  }
};

/**
 * POST /groupmember/register
 * Finalizes a group member: sets (or confirms) username, hashes the chosen password,
 * creates a profile, and (optionally) logs them in or redirects to success.
 * Expected form fields:
 *   - groupId, email  (to locate the pending GroupMember)
 *   - username, password
 *   - name (optional override; otherwise use existing)
 */
module.exports.registerGroupMember = async (req, res) => {
  try {
    const csrfToken = req.csrfToken ? req.csrfToken() : null;
    const { groupId, email, username, password, name } = req.body;

    if (!groupId || !email || !username || !password) {
      return res.status(400).render('member_form_views/completemember', {
        layout: 'memberformlayout',
        title: 'Complete Registration',
        csrfToken,
        errorMessage: 'Please complete all required fields.',
        leader: await Leader.findById(groupId).lean(),
        member: { email, name: name || '' }
      });
    }

    // Make sure the leader exists
    const leader = await Leader.findById(groupId);
    if (!leader) {
      return renderError(res, 'Leader/group not found.', 404);
    }

    // Find the in-flight (invited) member record
    const groupMember = await GroupMember.findOne({ groupId: leader._id, email });
    if (!groupMember) {
      return renderError(res, 'No pending group member found for that email.', 404);
    }

    // Uniqueness check on username (simple)
    const existingUser = await GroupMember.findOne({ username });
    if (existingUser && existingUser._id.toString() !== groupMember._id.toString()) {
      return res.status(400).render('member_form_views/completemember', {
        layout: 'memberformlayout',
        title: 'Complete Registration',
        csrfToken,
        errorMessage: 'That username is already taken.',
        leader: leader.toObject(),
        member: { email, name: name || groupMember.name }
      });
    }

    // Validate minimal fields with your util (mirrors server-side expectations)
    const validationErrors = validateGroupMemberData({
      groupId: leader._id.toString(),
      groupName: leader.groupName,
      name: name || groupMember.name,
      email,
      username,
      password
    });
    if (validationErrors.length) {
      return res.status(400).render('member_form_views/completemember', {
        layout: 'memberformlayout',
        title: 'Complete Registration',
        csrfToken,
        errorMessage: validationErrors.join(' '),
        leader: leader.toObject(),
        member: { email, name: name || groupMember.name }
      });
    }

    // Hash password, update record (NO topics here)
    const hashed = await bcrypt.hash(password, 10);
    groupMember.username = username;
    groupMember.password = hashed;
    if (name) groupMember.name = name;
    // If you track activation/verification flags on GroupMember, set them here:
    // groupMember.isActive = true;
    // groupMember.isVerified = true;
    await groupMember.save();

    // Create a basic profile if it doesn’t exist yet
    const existingProfile = await GroupMemberProfile.findOne({ groupMemberId: groupMember._id });
    if (!existingProfile) {
      await new GroupMemberProfile({
        groupMemberId: groupMember._id,
        name: groupMember.name,
        professionalTitle: '',
        profileImage: '/images/default-avatar.png',
        biography: '',
        goals: ''
      }).save();
    }

    // Optionally log in here with Passport (req.login) — or just show success
    // await new Promise((resolve, reject) => {
    //   req.login(groupMember, (err) => (err ? reject(err) : resolve()));
    // });

    return res.render('member_form_views/register_success', {
      layout: 'memberformlayout',
      title: 'Registration Successful',
      username: groupMember.username,
      user: groupMember,
      dashboardLink: '/dashboard' // change if you have a dedicated group member dashboard path
    });
  } catch (err) {
    console.error("❌ Error registering group member:", err.message);
    return renderError(res, 'An error occurred while completing your registration.');
  }
};
