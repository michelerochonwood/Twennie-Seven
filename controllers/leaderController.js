const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const { validateLeaderData } = require('../utils/validateLeader');
const { validateGroupMemberData } = require('../utils/validateGroupMember');
const LeaderProfile = require('../models/profile_models/leader_profile');

const GroupProfile = require('../models/profile_models/group_profile');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const baseUrl = process.env.BASE_URL || 'http://localhost:3000';




module.exports = {
    // Render the leader form
    showLeaderForm: (req, res) => {
        
        try {
            const csrfToken = req.csrfToken ? req.csrfToken() : null;
            res.render('member_form_views/form_leader', {
                layout: 'memberformlayout',
                title: 'Leader Membership Form',
                csrfToken,
            });
        } catch (err) {
            console.error('Error rendering leader form:', err.message);
            res.status(500).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Error',
                errorMessage: 'An error occurred while loading the leader form.',
            });
        }
    },

    // Handle leader form submission
// Handle leader form submission
createLeader: async (req, res) => {
    try {
const {
  groupName,
  groupLeaderName,
  professionalTitle,
  organization,
  industry, // ✅ THIS WAS MISSING
  username,
  groupLeaderEmail,
  password,
  line1,
  line2,
  city,
  province,
  postalCode,
  country,
  groupSize,
  topic1,
  topic2,
  topic3,
  members,
  registration_code,
  redirectTarget
} = req.body;
  
      console.log('Parsed members:', members);
  
      const leaderErrors = validateLeaderData(req.body);
      if (leaderErrors.length > 0) {
        console.error('Leader validation errors:', leaderErrors);
        return res.status(400).render('member_form_views/form_leader', {
          layout: 'memberformlayout',
          title: 'Leader Membership Form',
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          errorMessage: leaderErrors.join(" "),
        });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
const leader = new Leader({
  groupName,
  groupLeaderName,
  professionalTitle,
  organization,
  industry,
  username,
  groupLeaderEmail,
  password: hashedPassword,
  groupSize,
  topics: { topic1, topic2, topic3 },
  members: [],
  registration_code,
  accessLevel: 'paid_leader',
  billingAddress: {
    line1,
    line2,
    city,
    province,
    postalCode,
    country
  }
});

  
      const savedLeader = await leader.save();
      console.log('✅ Leader saved successfully:', savedLeader);
  
      const leaderProfile = new LeaderProfile({
        leaderId: savedLeader._id,
        name: savedLeader.groupLeaderName,
        professionalTitle: savedLeader.professionalTitle,
        profileImage: "/images/default-avatar.png",
        biography: "",
        goals: "",
        groupLeadershipGoals: "",
        topics: {
          topic1: topic1 || "Default Topic 1",
          topic2: topic2 || "Default Topic 2",
          topic3: topic3 || "Default Topic 3"
        }
      });
  
      await leaderProfile.save();
      console.log(`✅ Leader Profile Created: ${leaderProfile._id}`);
  
      const groupProfile = new GroupProfile({
        groupId: savedLeader._id,
        groupName: savedLeader.groupName,
        groupLeaderName: savedLeader.groupLeaderName,
        organization: savedLeader.organization,
        groupSize: savedLeader.groupSize,
        groupGoals: "",
        groupTopics: {
          topic1: topic1 || "Default Topic 1",
          topic2: topic2 || "Default Topic 2",
          topic3: topic3 || "Default Topic 3"
        },
        members: [],
        groupImage: "/images/default-group.png"
      });
  
      await groupProfile.save();
      console.log(`✅ Group Profile Created: ${groupProfile._id}`);
  
      const memberErrors = [];
      members.forEach((member, index) => {
        const errors = validateGroupMemberData({
          groupId: savedLeader._id.toString(),
          groupName,
          ...member,
          username: `member_${index}_${groupName.toLowerCase().replace(/\s+/g, '_')}`,
          password: 'defaultPassword123',
          topics: { topic1, topic2, topic3 },
        });
        if (errors.length > 0) {
          memberErrors.push(`Member ${index + 1}: ${errors.join(", ")}`);
        }
      });
  
      if (memberErrors.length > 0) {
        console.error('Group member validation errors:', memberErrors);
        return res.status(400).render('member_form_views/form_leader', {
          layout: 'memberformlayout',
          title: 'Leader Membership Form',
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          errorMessage: memberErrors.join(" "),
        });
      }
  
      console.log('Validation passed. Proceeding to save members.');
  
      const groupMemberPromises = members.map(async (member, index) => {
        const groupMember = new GroupMember({
          groupId: savedLeader._id,
          groupName,
          name: member.name,
          email: member.email,
          username: `member_${index}_${groupName.toLowerCase().replace(/\s+/g, '_')}`,
          password: await bcrypt.hash('defaultPassword123', 10),
          topics: { topic1, topic2, topic3 },
        });
  
        const savedMember = await groupMember.save();
        savedLeader.members.push(savedMember._id);
        return savedMember;
      });
  
      await Promise.all(groupMemberPromises);
      await savedLeader.save();
      console.log('All group members saved successfully.');
  
      req.session.user = {
        id: savedLeader._id,
        username: savedLeader.username,
        membershipType: savedLeader.membershipType,
      };
  
      // ✅ Stripe redirect for all leaders
      if (redirectTarget === 'payment') {
        const groupSizeInt = parseInt(groupSize);
        const unitAmount = groupSizeInt * 1700; // $17 per member in CAD cents
      
        // ✅ Create Stripe Customer with metadata
const customer = await stripe.customers.create({
  email: groupLeaderEmail,
  name: groupLeaderName,
  metadata: {
    leaderId: savedLeader._id.toString(),
    groupName: groupName
  },
  address: {
    line1,
    line2,
    city,
    state: province,
    postal_code: postalCode,
    country
  }
});

      
        // ✅ Save Stripe customer ID in Leader document
        savedLeader.stripeCustomerId = customer.id;
        await savedLeader.save();
      
        // ✅ Create product + price
        const product = await stripe.products.create({
          name: `Twennie Group Membership (${groupSizeInt} members)`
        });
      
        const price = await stripe.prices.create({
          unit_amount: unitAmount,
          currency: 'cad',
          recurring: { interval: 'month' },
          product: product.id,
          tax_behavior: 'exclusive'
        });
      
        // ✅ Create subscription checkout session
        const session = await stripe.checkout.sessions.create({
          customer: customer.id,
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [
            {
              price: price.id,
              quantity: 1,
            },
          ],
          automatic_tax: { enabled: true },
          billing_address_collection: 'required',
          success_url: `${baseUrl}/member/payment/success`,
          cancel_url: `${baseUrl}/member/payment/cancel`,
        });
      
        console.log(`✅ Stripe session created: ${session.id}`);
        return res.redirect(303, session.url);
      }
      
      
      
  
      // Default fallback (never hit in practice)
      res.render('member_form_views/register_success', {
        layout: 'memberformlayout',
        title: 'Registration Successful',
        username: savedLeader.username,
        user: savedLeader,
        dashboardLink: "/dashboard/leader"
      });
    } catch (err) {
      console.error('Error creating leader or group members:', err.message);
      res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An error occurred while creating the leader or group members.',
      });
    }
  },
  

    // Render the add group member form
    showAddGroupMemberForm: async (req, res) => {

        console.log('Rendering view: member_form_views/add_group_member');
        console.log(`showAddGroupMemberForm called with leaderId: ${req.params.leaderId}`);
        try {
            const { leaderId } = req.params;
    
            console.log(`Fetching leader with ID: ${leaderId}`);
    
            const leader = await Leader.findById(leaderId).lean();
    
            if (!leader) {
                return res.status(404).render('member_form_views/error', {
                    layout: 'mainlayout',
                    title: 'Leader Not Found',
                    errorMessage: 'The specified leader does not exist.',
                });
            }
    
            console.log('Leader fetched for add group member form:', leader);
    
            res.render('member_form_views/add_group_member', {
                layout: 'memberformlayout',
                title: 'Add Group Member',
                leader,
                csrfToken: req.csrfToken ? req.csrfToken() : null,
            });
        } catch (err) {
            console.error('Error rendering add group member form:', err.message);
            res.status(500).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Error',
                errorMessage: 'An unexpected error occurred while loading the group member form.',
            });
        }
    },
    
    
    

    // Handle submission of the add group member form
    addGroupMember: async (req, res) => {

        try {
            const { leaderId } = req.params;
            const { name, email } = req.body;
    
            const leader = await Leader.findById(leaderId);
    
            if (!leader) {
                return res.status(404).render('member_form_views/error', {
                    layout: 'mainlayout',
                    title: 'Leader Not Found',
                    errorMessage: 'The specified leader does not exist.',
                });
            }
    
            const groupMember = new GroupMember({
                groupId: leader._id,
                groupName: leader.groupName,
                name,
                email,
                username: `member_${leader.members.length}_${leader.groupName.toLowerCase().replace(/\s+/g, '_')}`,
                password: 'defaultPassword123',
                topics: leader.topics,
            });
    
            const savedMember = await groupMember.save();
            leader.members.push(savedMember._id);
            await leader.save();
    
            // Redirect to the dashboard
            res.redirect('/dashboard');
        } catch (err) {
            console.error('Error adding group member:', err.message);
            res.status(500).render('member_form_views/error', {
                layout: 'mainlayout',
                title: 'Error',
                errorMessage: 'An error occurred while adding the group member.',
            });
        }
    },
    

    // Function to update members for existing leaders
    updateMembers: async () => {

        try {
            const leaders = await Leader.find();
            for (const leader of leaders) {
                const groupMembers = await GroupMember.find({ groupId: leader._id });
                leader.members = groupMembers.map((member) => member._id);
                await leader.save();
                console.log(`Updated members for leader: ${leader.groupName}`);
            }
            console.log('Update complete!');
        } catch (err) {
            console.error('Error updating members:', err.message);
        }
    },
};

