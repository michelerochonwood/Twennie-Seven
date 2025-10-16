// controllers/groupmemberController.js
const bcrypt = require('bcrypt');
const GroupMember = require("../models/member_models/group_member");
const GroupMemberProfile = require("../models/profile_models/groupmember_profile");
const Leader = require("../models/member_models/leader");
const { validateGroupMemberData } = require("../utils/validateGroupMember");

// ---- helpers ----
function renderError(res, message, status = 500) {
  return res.status(status).render('member_form_views/error', {
    layout: 'mainlayout',
    title: 'Error',
    errorMessage: message,
  });
}

module.exports = {
  // --- GET /member/group/verify ---
  showVerifyMemberForm: async (req, res) => {
    try {
      const csrfToken = req.csrfToken ? req.csrfToken() : null;

      // Join Leaders with their GroupMembers (idempotent; view decides how to present)
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

      return res.render('member_form_views/verifymember', {
        layout: 'memberformlayout',
        title: 'Verify Group Membership',
        csrfToken,
        groups
      });
    } catch (err) {
      console.error('Error rendering verify member form:', err.message);
      return renderError(res, 'An error occurred while loading the verification form.');
    }
  },

  // --- POST /member/group/verify-member (optional AJAX) ---
  verifyMember: async (req, res) => {
    try {
      const { memberName, memberEmail, groupId } = req.body;
      const gm = await GroupMember.findOne({
        groupId,
        name: memberName,
        email: memberEmail
      });
      if (!gm) {
        return res.status(400).json({ valid: false, error: "Member not found in the group." });
      }
      return res.json({ valid: true, member: { name: gm.name, email: gm.email } });
    } catch (err) {
      console.error("❌ Error verifying group member:", err.message);
      return res.status(500).json({ valid: false, error: "Server error during verification." });
    }
  },

  // --- POST /member/group/verify-registration-code ---
  verifyRegistrationCode: async (req, res) => {
    try {
      const csrfToken = req.csrfToken ? req.csrfToken() : null;
      const { groupId, registration_code } = req.body;

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

      groups.forEach(group => {
        const isMatch = group._id.toString() === groupId;
        group.verified = Boolean(isMatch && leader && leader.registration_code === registration_code);
        group.error = Boolean(isMatch && !group.verified);
      });

      return res.status(200).render("member_form_views/verifymember", {
        layout: "memberformlayout",
        title: "Verify Group Membership",
        csrfToken,
        groups
      });
    } catch (err) {
      console.error("❌ Error verifying registration code:", err.message);
      return renderError(res, "An error occurred while verifying the registration code.");
    }
  },

  // --- GET /member/group/complete-registration ---
  // Accepts either:
  //   ?groupId=<id>&email=<email>
  // or legacy:
  //   ?memberName=&memberEmail=&groupId=&groupName=
  showCompleteMemberForm: async (req, res) => {
    try {
      const csrfToken = req.csrfToken ? req.csrfToken() : null;
      const groupId = req.query.groupId;
      const email = (req.query.email || req.query.memberEmail || '').toLowerCase();
      const nameFromQuery = req.query.name || req.query.memberName || '';
      const groupNameFromQuery = req.query.groupName || '';

      if (!groupId || !email) {
        return renderError(res, 'Invalid request. Missing groupId or email.', 400);
      }

      const leader = await Leader.findById(groupId).lean();
      if (!leader) {
        return renderError(res, 'Leader/group not found.', 404);
      }

      const member = await GroupMember.findOne({ groupId: leader._id, email }).lean();
      if (!member) {
        return renderError(res, 'No matching group member found for that email.', 404);
      }

      const memberInfo = {
        name: member.name || nameFromQuery || '',
        email: member.email,
        groupId: leader._id.toString(),
        groupName: leader.groupName || groupNameFromQuery || ''
      };

      return res.render("member_form_views/completemember", {
        layout: "memberformlayout",
        title: "Complete Group Membership",
        memberInfo,
        csrfToken
      });
    } catch (err) {
      console.error("❌ Error loading complete registration form:", err.message);
      return renderError(res, "An error occurred while loading the complete registration form.");
    }
  },

  // --- POST /member/group/register ---
  registerGroupMember: async (req, res) => {
    try {
      const csrfToken = req.csrfToken ? req.csrfToken() : null;
      const {
        groupId,
        groupName,
        name,
        email,
        username,
        password,
        professionalTitle,
        topics // optional; you send it from your form
      } = req.body;

      // Basic presence checks
      if (!groupId || !email || !username || !password) {
        return res.status(400).render("member_form_views/completemember", {
          layout: "memberformlayout",
          title: "Complete Group Membership",
          memberInfo: { groupId, groupName, name, email },
          csrfToken,
          errorMessage: 'Please complete all required fields.'
        });
      }

      // Validate via util
      const validationErrors = validateGroupMemberData({
        groupId,
        groupName,
        name,
        email,
        username,
        password
      });
      if (validationErrors.length) {
        return res.status(400).render('member_form_views/completemember', {
          layout: 'memberformlayout',
          title: 'Complete Group Membership',
          memberInfo: { groupId, groupName, name, email },
          csrfToken,
          errorMessage: validationErrors.join(' ')
        });
      }

      // Load invited doc
      const gm = await GroupMember.findOne({ groupId, name, email });
      if (!gm) {
        return res.status(404).render('member_form_views/completemember', {
          layout: 'memberformlayout',
          title: 'Complete Group Membership',
          memberInfo: { groupId, groupName, name, email },
          csrfToken,
          errorMessage: 'Group member not found.'
        });
      }

      // Uniqueness checks (exclude self)
      const existingUser = await GroupMember.findOne({
        _id: { $ne: gm._id },
        $or: [{ username }, { email }]
      });
      if (existingUser) {
        return res.status(400).render('member_form_views/completemember', {
          layout: 'memberformlayout',
          title: 'Complete Group Membership',
          memberInfo: { groupId, groupName, name, email },
          csrfToken,
          errorMessage: 'Username or email is already registered.'
        });
      }

      // Update + hash password
      gm.username = username;
      gm.password = await bcrypt.hash(password, 10);
      gm.isVerified = true;
      if (professionalTitle) gm.professionalTitle = professionalTitle;
      // topics are optional now; set only if provided
      if (topics && typeof topics === 'object') {
        gm.topics = {
          topic1: topics.topic1 || gm.topics?.topic1,
          topic2: topics.topic2 || gm.topics?.topic2,
          topic3: topics.topic3 || gm.topics?.topic3
        };
      }
      await gm.save();
      console.log("✅ Group member registered successfully:", gm._id.toString());

      // Ensure profile exists or create a basic one
      let profile = await GroupMemberProfile.findOne({ groupMemberId: gm._id });
      if (!profile) {
        profile = new GroupMemberProfile({
          groupMemberId: gm._id,
          name: gm.name,
          professionalTitle: gm.professionalTitle || '',
          profileImage: '/images/default-avatar.png',
          biography: '',
          goals: '',
          // topics optional
          topics: (topics && (topics.topic1 || topics.topic2 || topics.topic3)) ? {
            topic1: topics.topic1 || '',
            topic2: topics.topic2 || '',
            topic3: topics.topic3 || ''
          } : undefined
        });
        await profile.save();
        console.log(`✅ Group Member Profile Created: ${profile._id}`);
      }

      // Set session + redirect
// ---- Immediately log in user & redirect to success (PRG pattern) ----
req.session.user = {
  id: gm._id.toString(),
  username: gm.username,
  membershipType: 'group_member'
};

return req.session.save(err => {
  if (err) {
    console.error("❌ Error saving session:", err);
    return renderError(res, "An error occurred while logging in after registration.");
  }

  // Non-blocking profile creation: do not let this prevent redirect
  (async () => {
    try {
      const exists = await GroupMemberProfile.findOne({ groupMemberId: gm._id });
      if (!exists) {
        await new GroupMemberProfile({
          groupMemberId: gm._id,
          name: gm.name,
          professionalTitle: gm.professionalTitle || '',
          profileImage: '/images/default-avatar.png',
          biography: '',
          goals: '',
          topics: (topics && (topics.topic1 || topics.topic2 || topics.topic3)) ? {
            topic1: topics.topic1 || '',
            topic2: topics.topic2 || '',
            topic3: topics.topic3 || ''
          } : undefined
        }).save();
        console.log(`✅ Group Member Profile Created (non-blocking): ${gm._id}`);
      }
    } catch (e) {
      console.error('⚠️ Non-fatal: failed to create GroupMemberProfile', e);
    }
  })();
console.log('➡️ Redirecting to /member/group/register_success for', gm.username);
  // Redirect so the browser hits a clean GET and the success view picks up session state
  return res.redirect('/member/group/register_success');
});

    } catch (err) {
      console.error("❌ Error registering group member:", err.message);
      return renderError(res, "An error occurred while registering the group member.");
    }
  }
};
