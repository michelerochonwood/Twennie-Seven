// controllers/leaderController.js
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupProfile = require('../models/profile_models/group_profile');

const { validateLeaderData } = require('../utils/validateLeader');
const { validateGroupMemberData } = require('../utils/validateGroupMember');

const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

// Field whitelist (flat fields set directly on Leader)
const ALLOWED_LEADER_FIELDS = [
  'groupName',
  'groupLeaderName',
  'professionalTitle',
  'organization',
  'industry',
  'username',
  'groupLeaderEmail',
  'groupSize',
  'registration_code'
];

const pick = (obj, keys) =>
  keys.reduce((acc, k) => (obj[k] !== undefined ? (acc[k] = obj[k], acc) : acc), {});

// Utility: normalize “members” from forms (array or JSON string or undefined)
function coerceMembers(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

module.exports = {
  // Render the leader form
  showLeaderForm: (req, res) => {
    try {
      const csrfToken = req.csrfToken ? req.csrfToken() : null;
      res.render('member_form_views/form_leader', {
        layout: 'memberformlayout',
        title: 'Leader Membership Form',
        csrfToken
      });
    } catch (err) {
      console.error('Error rendering leader form:', err.message);
      res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading the leader form.'
      });
    }
  },

  // Handle leader form submission
  createLeader: async (req, res) => {
    try {
      const {
        groupName,
        groupLeaderName,
        professionalTitle,
        organization,
        industry,
        username,
        groupLeaderEmail,
        password,
        // Optional address fields from form (currently not displayed, so likely undefined)
        line1, line2, city, province, postalCode, country,
        groupSize,
        topic1, topic2, topic3,
        members, // may be array or JSON string
        registration_code,
        redirectTarget
      } = req.body;

      // 1) Validate leader payload
      const leaderErrors = validateLeaderData(req.body);
      if (leaderErrors.length > 0) {
        console.error('Leader validation errors:', leaderErrors);
        return res.status(400).render('member_form_views/form_leader', {
          layout: 'memberformlayout',
          title: 'Leader Membership Form',
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          errorMessage: leaderErrors.join(' ')
        });
      }

      // 2) Hash leader password
      const hashedPassword = await bcrypt.hash(password, 10);

      // 3) Build safe Leader doc
      const base = pick(req.body, ALLOWED_LEADER_FIELDS);
      const leader = new Leader({
        ...base,
        password: hashedPassword,
        topics: { topic1, topic2, topic3 },
        members: [],
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
      console.log('✅ Leader saved successfully:', savedLeader._id.toString());

      // 4) Create LeaderProfile
      const leaderProfile = new LeaderProfile({
        leaderId: savedLeader._id,
        name: savedLeader.groupLeaderName,
        professionalTitle: savedLeader.professionalTitle,
        profileImage: '/images/default-avatar.png',
        biography: '',
        goals: '',
        groupLeadershipGoals: '',
        topics: {
          topic1: topic1 || 'Default Topic 1',
          topic2: topic2 || 'Default Topic 2',
          topic3: topic3 || 'Default Topic 3'
        }
      });
      await leaderProfile.save();
      console.log(`✅ Leader Profile Created: ${leaderProfile._id}`);

      // 5) Create GroupProfile
      const groupProfile = new GroupProfile({
        groupId: savedLeader._id,
        groupName: savedLeader.groupName,
        groupLeaderName: savedLeader.groupLeaderName,
        organization: savedLeader.organization,
        groupSize: savedLeader.groupSize,
        groupGoals: '',
        groupTopics: {
          topic1: topic1 || 'Default Topic 1',
          topic2: topic2 || 'Default Topic 2',
          topic3: topic3 || 'Default Topic 3'
        },
        members: [],
        groupImage: '/images/default-group.png'
      });
      await groupProfile.save();
      console.log(`✅ Group Profile Created: ${groupProfile._id}`);

      // 6) Validate & create GroupMembers (default password, hashed)
      const memberList = coerceMembers(members);
      const memberErrors = [];

      memberList.forEach((m, index) => {
        const errors = validateGroupMemberData({
          groupId: savedLeader._id.toString(),
          groupName,
          ...m,
          username: `member_${index}_${groupName.toLowerCase().replace(/\s+/g, '_')}`,
          password: 'defaultPassword123',
          topics: { topic1, topic2, topic3 }
        });
        if (errors.length > 0) memberErrors.push(`Member ${index + 1}: ${errors.join(', ')}`);
      });

      if (memberErrors.length > 0) {
        console.error('Group member validation errors:', memberErrors);
        return res.status(400).render('member_form_views/form_leader', {
          layout: 'memberformlayout',
          title: 'Leader Membership Form',
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          errorMessage: memberErrors.join(' ')
        });
      }

      // Save group members
      const groupMemberPromises = memberList.map(async (m, index) => {
        const gm = new GroupMember({
          groupId: savedLeader._id,
          groupName,
          name: m.name,
          email: m.email,
          username: `member_${index}_${groupName.toLowerCase().replace(/\s+/g, '_')}`,
          password: await bcrypt.hash('defaultPassword123', 10),
          topics: { topic1, topic2, topic3 }
        });
        const savedMember = await gm.save();
        savedLeader.members.push(savedMember._id);
        return savedMember;
      });

      await Promise.all(groupMemberPromises);
      await savedLeader.save();
      console.log('✅ All group members saved successfully.');

      // 7) (Optional) Passport session; you can keep your existing login flow instead
      // await new Promise((resolve, reject) => {
      //   req.login(savedLeader, (err) => (err ? reject(err) : resolve()));
      // });

      // 8) Stripe (payment redirect if requested)
// … after you've built memberList and saved members …

// Stripe (payment redirect if requested)
if (redirectTarget === 'payment') {
  // Prefer the actual submitted members length for accuracy
  const memberList = coerceMembers(members);
  const memberCount = Array.isArray(memberList) ? memberList.length : 0;

  // Seats = leader (1) + members
  const seats = 1 + memberCount;

  // Optional: sanity-check if dropdown groupSize matches memberCount
  const groupSizeInt = parseInt(groupSize, 10);
  if (Number.isFinite(groupSizeInt) && groupSizeInt !== memberCount) {
    console.warn(`⚠️ groupSize (${groupSizeInt}) != memberCount (${memberCount}) – using seats=${seats}`);
  }

  const unitAmount = seats * 1700; // $17 CAD in cents per seat

  // Create Stripe Customer (no partial address; Checkout will save it)
  const customer = await stripe.customers.create({
    email: groupLeaderEmail,
    name: groupLeaderName,
    metadata: {
      leaderId: savedLeader._id.toString(),
      groupName,
      seats: String(seats),
      members: String(memberCount)
    }
  });

  savedLeader.stripeCustomerId = customer.id;
  await savedLeader.save();

  // Create product & price (you can reuse in prod if you want)
  const product = await stripe.products.create({
    name: `Twennie Group Membership (${seats} seats)`
  });

  const price = await stripe.prices.create({
    unit_amount: unitAmount,
    currency: 'cad',
    recurring: { interval: 'month' },
    product: product.id,
    tax_behavior: 'exclusive'
  });

  const session = await stripe.checkout.sessions.create({
    customer: customer.id,
    payment_method_types: ['card'],
    mode: 'subscription',
    line_items: [{ price: price.id, quantity: 1 }],
    automatic_tax: { enabled: true },
    billing_address_collection: 'required',
    customer_update: { address: 'auto', name: 'auto' },
    success_url: `${baseUrl}/member/payment/success`,
    cancel_url: `${baseUrl}/member/payment/cancel`
  });

  console.log(`✅ Stripe session created: ${session.id} | seats=${seats} amount=${unitAmount}`);
  return res.redirect(303, session.url);
}


      // 9) Default success page (non-payment path)
      return res.render('member_form_views/register_success', {
        layout: 'memberformlayout',
        title: 'Registration Successful',
        username: savedLeader.username,
        user: savedLeader,
        dashboardLink: '/dashboard/leader'
      });
    } catch (err) {
      console.error('Error creating leader or group members:', err.message);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An error occurred while creating the leader or group members.'
      });
    }
  },

  // Render the add group member form
  showAddGroupMemberForm: async (req, res) => {
    console.log('Rendering view: member_form_views/add_group_member');
    console.log(`showAddGroupMemberForm called with leaderId: ${req.params.leaderId}`);
    try {
      const { leaderId } = req.params;
      const leader = await Leader.findById(leaderId).lean();

      if (!leader) {
        return res.status(404).render('member_form_views/error', {
          layout: 'mainlayout',
          title: 'Leader Not Found',
          errorMessage: 'The specified leader does not exist.'
        });
      }

      console.log('Leader fetched for add group member form:', leader);

      res.render('member_form_views/add_group_member', {
        layout: 'memberformlayout',
        title: 'Add Group Member',
        leader,
        csrfToken: req.csrfToken ? req.csrfToken() : null
      });
    } catch (err) {
      console.error('Error rendering add group member form:', err.message);
      res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An unexpected error occurred while loading the group member form.'
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
          errorMessage: 'The specified leader does not exist.'
        });
      }

      // Validate using the same util
      const vErrors = validateGroupMemberData({
        groupId: leader._id.toString(),
        groupName: leader.groupName,
        name,
        email,
        username: `member_${leader.members.length}_${leader.groupName.toLowerCase().replace(/\s+/g, '_')}`,
        password: 'defaultPassword123'
      });
      if (vErrors.length) {
        return res.status(400).render('member_form_views/add_group_member', {
          layout: 'memberformlayout',
          title: 'Add Group Member',
          leader: leader.toObject(),
          csrfToken: req.csrfToken ? req.csrfToken() : null,
          errorMessage: vErrors.join(' ')
        });
      }

      const hashed = await bcrypt.hash('defaultPassword123', 10);

      const groupMember = new GroupMember({
        groupId: leader._id,
        groupName: leader.groupName,
        name,
        email,
        username: `member_${leader.members.length}_${leader.groupName.toLowerCase().replace(/\s+/g, '_')}`,
        password: hashed,
        topics: leader.topics
      });

      const savedMember = await groupMember.save();
      leader.members.push(savedMember._id);
      await leader.save();

      return res.redirect('/dashboard');
    } catch (err) {
      console.error('Error adding group member:', err.message);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An error occurred while adding the group member.'
      });
    }
  },

  // Utility to resync member ObjectIds on leaders
  updateMembers: async () => {
    try {
      const leaders = await Leader.find();
      for (const leader of leaders) {
        const groupMembers = await GroupMember.find({ groupId: leader._id });
        leader.members = groupMembers.map((m) => m._id);
        await leader.save();
        console.log(`Updated members for leader: ${leader.groupName}`);
      }
      console.log('Update complete!');
    } catch (err) {
      console.error('Error updating members:', err.message);
    }
  }
};

