const GroupMember = require("../models/member_models/group_member");
const GroupMemberProfile = require("../models/profile_models/groupmember_profile");
const Leader = require("../models/member_models/leader");
const { validateGroupMemberData } = require("../utils/validateGroupMember");
const bcrypt = require('bcrypt');





module.exports = {
    // Render the verification form
    showVerifyMemberForm: async (req, res) => {

        try {
            console.log('Fetching groups with aggregation...');
            
            // Use aggregation to join GroupMember documents with Leader documents
            const groups = await Leader.aggregate([
                {
                    $lookup: {
                        from: 'groupmembers', // Collection name for GroupMember
                        localField: '_id', // Leader's _id
                        foreignField: 'groupId', // GroupMember's groupId
                        as: 'members', // Output alias
                    },
                },
            ]);

            console.log('Fetched groups with members:', JSON.stringify(groups, null, 2));

res.render('member_form_views/verifymember', {
  layout: 'memberformlayout',
  title: 'Verify Group Membership',
  groups,
});

        } catch (err) {
            console.error('Error rendering verify member form:', err.message);
            res.status(500).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Error',
                errorMessage: 'An error occurred while loading the verification form.',
            });
        }
    },

    // Handle member verification
// Handle member verification (No registration code needed)
verifyMember: async (req, res) => {

    try {
        const { memberName, memberEmail, groupId, groupName } = req.body;

        console.log(`🔎 Verifying member for Group ID: ${groupId}`);
        
        // Find the group member by name, email, and group ID
        const groupMember = await GroupMember.findOne({
            groupId,
            name: memberName,
            email: memberEmail,
        });

        if (!groupMember) {
            console.error(`❌ No matching member found in Group ID: ${groupId}`);
            return res.status(400).json({ valid: false, error: "Member not found in the group." });
        }

        console.log(`✅ Member found: ${groupMember.name}`);

        // Return success response
        res.json({ valid: true, member: { name: groupMember.name, email: groupMember.email } });
    } catch (err) {
        console.error("❌ Error verifying group member:", err.message);
        res.status(500).json({ valid: false, error: "Server error during verification." });
    }
},

verifyRegistrationCode: async (req, res) => {
  try {
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

    // Flag verification status per group
    groups.forEach(group => {
      const isMatch = group._id.toString() === groupId;
      group.verified = isMatch && leader && leader.registration_code === registration_code;
      group.error = isMatch && !group.verified;
    });

    return res.status(200).render("member_form_views/verifymember", {
      layout: "memberformlayout",
      title: "Verify Group Membership",
      groups,
    });

  } catch (err) {
    console.error("❌ Error verifying registration code:", err.message);
    return res.status(500).render("member_form_views/error", {
      layout: "memberformlayout",
      title: "Error",
      errorMessage: "An error occurred while verifying the registration code."
    });
  }
},




    

    // Handle member registration
    registerGroupMember: async (req, res) => {

        try {
            const {
                groupId,
                groupName,
                name,
                email,
                username,
                password,
                professionalTitle, // Ensure professionalTitle is included
                topics // Ensure topics are included
            } = req.body;
    
            // ✅ Validate group member data
            const errors = validateGroupMemberData(req.body);
            if (errors.length > 0) {
                console.error("Validation errors:", errors);
                return res.status(400).render("member_form_views/completemember", {
                    layout: "memberformlayout",
                    title: "Complete Group Membership",
                    memberInfo: { groupId, groupName, name, email },
                    errorMessage: errors.join(" "),
                });
            }
    
            // ✅ Find the existing group member by groupId, name, and email
            const groupMember = await GroupMember.findOne({
                groupId,
                name,
                email,
            });

            if (!groupMember) {
                return res.status(404).render("member_form_views/completemember", {
                    layout: "memberformlayout",
                    title: "Complete Group Membership",
                    memberInfo: { groupId, groupName, name, email },
                    errorMessage: "Group member not found.",
                });
            }
    
            // ✅ Check if the username or email is already registered
            const existingMember = await GroupMember.findOne({
                $or: [{ username }, { email }],
                _id: { $ne: groupMember._id },
            });

            if (existingMember) {
                return res.status(400).render("member_form_views/completemember", {
                    layout: "memberformlayout",
                    title: "Complete Group Membership",
                    memberInfo: { groupId, groupName, name, email },
                    errorMessage: "Username or email is already registered.",
                });
            }
    
            // ✅ Update the group member's information
// ✅ Update the group member's information
groupMember.username = username;
groupMember.password = await bcrypt.hash(password, 10); // ✅ Secure password
groupMember.isVerified = true;
groupMember.professionalTitle = professionalTitle;

await groupMember.save();

    
            console.log("✅ Group member registered successfully:", groupMember);
    
            // ✅ Automatically create a profile for the new group member
            const groupMemberProfile = new GroupMemberProfile({
                groupMemberId: groupMember._id,
                name: groupMember.name,
                professionalTitle: professionalTitle || "", // Assign professionalTitle
                profileImage: "/images/default-avatar.png", // Default image
                biography: "",
                goals: "",
                topics: {
                    topic1: topics?.topic1 || "Default Topic 1",
                    topic2: topics?.topic2 || "Default Topic 2",
                    topic3: topics?.topic3 || "Default Topic 3"
                }
            });

            await groupMemberProfile.save();

            console.log(`✅ Group Member Profile Created: ${groupMemberProfile._id}`);

            // ✅ Set session for the registered group member
            req.session.user = {
                id: groupMember._id,
                username: groupMember.username,
                membershipType: "groupmember", 
            };
    
            req.session.save(err => {
                if (err) {
                    console.error("❌ Error saving session:", err);
                    return res.status(500).render("member_form_views/error", {
                        layout: "mainlayout",
                        title: "Error",
                        errorMessage: "An error occurred while logging in after registration."
                    });
                }
    
                // ✅ Redirect to the success page, ensuring session persistence
                res.render("member_form_views/register_success", {
                    layout: "memberformlayout",
                    title: "Registration Successful",
                    username: groupMember.username,
                    user: groupMember, // Pass the full group member object for the header
                    dashboardLink: "/dashboard/groupmember"
                });
            });
    
        } catch (err) {
            console.error("❌ Error registering group member:", err.message);
            res.status(500).render("member_form_views/error", {
                layout: "mainlayout",
                title: "Error",
                errorMessage: "An error occurred while registering the group member.",
            });
        }
    },



showCompleteMemberForm: async (req, res) => {
  try {
    const { memberName, memberEmail, groupId, groupName } = req.query;

    console.log(`🔎 Redirecting to complete registration for member: ${memberName}, Group ID: ${groupId}`);

    if (!memberName || !memberEmail || !groupId || !groupName) {
      return res.status(400).render("member_form_views/error", {
        layout: "mainlayout",
        title: "Error",
        errorMessage: "Invalid request. Missing member information.",
      });
    }

    const memberInfo = { name: memberName, email: memberEmail, groupId, groupName };

    res.render("member_form_views/completemember", {
      layout: "memberformlayout",
      title: "Complete Group Membership",
      memberInfo,
      csrfToken: req.csrfToken() // ✅ This line is required
    });
  } catch (err) {
    console.error("❌ Error redirecting to complete registration:", err.message);
    res.status(500).render("member_form_views/error", {
      layout: "mainlayout",
      title: "Error",
      errorMessage: "An error occurred while loading the complete registration form.",
    });
  }
}

    
};
