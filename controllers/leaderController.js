// controllers/leaderController.js
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
const { validateLeaderData } = require('../utils/validateLeader');
const { validateGroupMemberData } = require('../utils/validateGroupMember');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupProfile = require('../models/profile_models/group_profile');
const Organization = require('../models/member_models/organization');
const OrganizationJoinRequest = require('../models/member_models/organization_join_request');


const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

function slugifyOrgName(name = '') {
  return name
    .toString()
    .trim()
    .toLowerCase()
    .replace(/&/g, 'and')
    .replace(/[^a-z0-9]+/g, '-')  // collapse non-alphanum to hyphen
    .replace(/^-+|-+$/g, '')      // trim leading/trailing hyphens
    .slice(0, 140);
}

function parseDomains(raw) {
  if (!raw) return [];
  // accept comma-separated string
  if (typeof raw === 'string') {
    return raw
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean)
      .filter(d => d.includes('.') && !d.includes(' '));
  }
  // accept array if you ever switch the form
  if (Array.isArray(raw)) {
    return raw
      .map(s => String(s).trim().toLowerCase())
      .filter(Boolean)
      .filter(d => d.includes('.') && !d.includes(' '));
  }
  return [];
}

async function buildUniqueSlug(baseSlug) {
  if (!baseSlug) baseSlug = 'organization';
  let slug = baseSlug;
  let n = 2;

  // Try base first, then base-2, base-3...
  // Using countDocuments keeps it fast and simple.
  while (await Organization.countDocuments({ slug }) > 0) {
    slug = `${baseSlug}-${n}`;
    n += 1;
  }
  return slug;
}


// Prefer configured BASE_URL; otherwise derive from request (proxy aware)
function getSuccessBase(req) {
  const env = process.env.BASE_URL;
  if (env && /^https?:\/\//.test(env)) return env.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https');
  const host  = (req.headers['x-forwarded-host']  || req.get('host'));
  return `${proto}://${host}`;
}

// Normalize “members” from forms (array or JSON string or undefined)
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
  createLeader: async (req, res) => {
    try {
const {
  groupName,
  groupLeaderName,
  professionalTitle,
  industry,
  username,
  groupLeaderEmail,
  password,
  line1, line2, city, province, postalCode, country,
  groupSize,
  topic1, topic2, topic3,
  members,
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
          errorMessage: leaderErrors.join(" "),
        });
      }

      // 2) Hash leader password
      const hashedPassword = await bcrypt.hash(password, 10);

      // 3) Create Leader (keeps topics because your schema currently has them)
const leader = new Leader({
  groupName,
  groupLeaderName,
  professionalTitle,

  // Organization is created later via success-page flow
  organization: null,
  organizationOptOut: false,
  organizationName: '',

  industry,
  username,
  groupLeaderEmail,
  password: hashedPassword,
  groupSize,
  topics: { topic1, topic2, topic3 },
  members: [],
  registration_code,
  billingAddress: { line1, line2, city, province, postalCode, country }
});


      const savedLeader = await leader.save();
      console.log('✅ Leader saved successfully:', savedLeader._id.toString());

      // 4) Leader Profile
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

// 5) Group Profile (idempotent; prevents duplicates)
const groupProfile = await GroupProfile.findOneAndUpdate(
  { groupId: savedLeader._id },
  {
    $setOnInsert: {
      groupId: savedLeader._id,
      groupName: savedLeader.groupName,
      groupLeaderName: savedLeader.groupLeaderName,
      organization: savedLeader.organization, // null at creation time is fine
      groupSize: savedLeader.groupSize,
      groupGoals: "",
      groupTopics: {
        topic1: topic1 || "Default Topic 1",
        topic2: topic2 || "Default Topic 2",
        topic3: topic3 || "Default Topic 3"
      },
      members: [],
      groupImage: "/images/default-group.png"
    }
  },
  { upsert: true, new: true, setDefaultsOnInsert: true }
);

console.log(`✅ Group Profile ensured: ${groupProfile._id}`);


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
        if (errors.length > 0) memberErrors.push(`Member ${index + 1}: ${errors.join(", ")}`);
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

      const groupMemberPromises = memberList.map(async (m, index) => {
const gm = new GroupMember({
  // ✅ required leader reference (if your schema uses it)
  leader: savedLeader._id,

  // ✅ keep your existing group linkage
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

      // Lightweight session snapshot
      req.session.user = {
        id: savedLeader._id.toString(),
        username: savedLeader.username,
        membershipType: savedLeader.membershipType,
      };

      // 7) Stripe Checkout (if requested)
      if (redirectTarget === 'payment') {
        // Seats = leader (1) + actual members submitted
        const count = Array.isArray(memberList) ? memberList.length : 0;
        const seats = 1 + count;

        // Log mismatch if dropdown disagrees (we still bill by actual members)
        const groupSizeInt = parseInt(groupSize, 10);
        if (Number.isFinite(groupSizeInt) && groupSizeInt !== count) {
          console.warn(`⚠️ groupSize (${groupSizeInt}) != memberCount (${count}) – using seats=${seats}`);
        }

        const unitAmount = seats * 1700; // $17 CAD in cents per seat

        // Create Stripe Customer (NO partial address here; let Checkout save it)
        const customer = await stripe.customers.create({
          email: groupLeaderEmail,
          name: groupLeaderName,
          metadata: {
            leaderId: savedLeader._id.toString(),
            groupName: groupName,
            seats: String(seats),
            members: String(count)
          }
        });

        // Save Stripe customer ID
        savedLeader.stripeCustomerId = customer.id;
        await savedLeader.save();

        // Create product & price (one-off per checkout, fine for now)
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

        // Success/cancel URLs
        const successBase = getSuccessBase(req);
        const session = await stripe.checkout.sessions.create({
          customer: customer.id,
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [{ price: price.id, quantity: 1 }],
          automatic_tax: { enabled: true },
          billing_address_collection: 'required',
          // Let Checkout collect + save address & name to the Customer
          customer_update: { address: 'auto', name: 'auto' },
          success_url: `${successBase}/member/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url:  `${successBase}/member/payment/cancel`
        });

        console.log(`✅ Stripe session created: ${session.id} | seats=${seats} amount=${unitAmount}`);
        return res.redirect(303, session.url);
      }

      // Fallback (non-payment path)
return res.render('member_form_views/register_success', {
  layout: 'memberformlayout',
  title: 'Registration Successful',
  username: savedLeader.username,
  user: savedLeader,
  dashboardLink: "/dashboard/leader",
  csrfToken: req.csrfToken ? req.csrfToken() : null
});

    } catch (err) {
      console.error('Error creating leader or group members:', err.message);
      return res.status(500).render('member_form_views/error', {
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
  // ✅ REQUIRED by GroupMember schema
  leader: leader._id,

  // ✅ REQUIRED by GroupMember schema
  groupName: leader.groupName,

  // Optional but strongly recommended (matches your schema)
  organization: leader.organization || null,
  organizationName: leader.organizationName || '',

  // Required user fields
  name,
  email,
  username: `member_${leader.members.length}_${leader.groupName.toLowerCase().replace(/\s+/g, '_')}`,
  password: await bcrypt.hash('defaultPassword123', 10),
});


      const savedMember = await groupMember.save();
      leader.members.push(savedMember._id);
      await leader.save();

      // Redirect to the dashboard
// Redirect to the success page for a clean GET
return res.redirect(`/leader/${leader._id}/add_group_member/success?memberId=${savedMember._id.toString()}`);

    } catch (err) {
      console.error('Error adding group member:', err.message);
      return res.status(500).render('member_form_views/error', {
        layout: 'mainlayout',
        title: 'Error',
        errorMessage: 'An error occurred while adding the group member.',
      });
    }
  },

  // Utility to update members list for all leaders
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
  },

  // Renders success page after adding a group member
showAddGroupMemberSuccess: async (req, res) => {
  try {
    const { leaderId } = req.params;
    const { memberId } = req.query;

    const [leader, member] = await Promise.all([
      Leader.findById(leaderId).select('groupName registration_code').lean(),
      GroupMember.findById(memberId).select('name email username').lean()
    ]);

    if (!leader || !member) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'We could not find that leader or group member.'
      });
    }

return res.render('member_form_views/new_member_success', {
  layout: 'memberformlayout',
  title: 'Member Added',
  leader,
  member
});
  } catch (err) {
    console.error('Error rendering add_group_member_success:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'An error occurred after adding the group member.'
    });
  }
},

// --- Show Delete Group Member page ---
showDeleteGroupMemberForm: async (req, res) => {
  try {
    const { leaderId } = req.params;

    const leader = await Leader.findById(leaderId)
      .select('groupName members')
      .populate({
        path: 'members',
        model: 'GroupMember',
        select: 'name email professionalTitle'
      });

    if (!leader) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Leader Not Found',
        errorMessage: 'The specified leader does not exist.'
      });
    }

    // Attach profile images (new schema uses groupMemberId)
    const membersWithImages = await Promise.all(
      (leader.members || []).map(async (m) => {
        const profile = await require('../models/profile_models/groupmember_profile')
          .findOne({ groupMemberId: m._id })
          .select('profileImage')
          .lean();
        return {
          _id: m._id,
          name: m.name,
          email: m.email,
          professionalTitle: m.professionalTitle || '',
          profileImage: profile?.profileImage || '/images/default-avatar.png'
        };
      })
    );

    return res.render('member_form_views/delete_group_member', {
      layout: 'memberformlayout',
      title: 'Delete Group Member',
      leader: { _id: leaderId, groupName: leader.groupName },
      members: membersWithImages,
      csrfToken: req.csrfToken ? req.csrfToken() : null,
      deleted: req.query.deleted === '1'
    });
  } catch (err) {
    console.error('Error rendering delete group member form:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'An unexpected error occurred while loading the delete page.'
    });
  }
},

// --- Handle Delete Group Member POST ---
deleteGroupMember: async (req, res) => {
  try {
    const { leaderId } = req.params;
    const { memberId } = req.body;

    // Basic guard
    const [leader, member] = await Promise.all([
      Leader.findById(leaderId).select('_id'),
      GroupMember.findById(memberId).select('_id groupId')
    ]);

    if (!leader || !member) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'Leader or group member not found.'
      });
    }

    if (String(member.groupId) !== String(leader._id)) {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Access Denied',
        errorMessage: 'This member does not belong to the specified leader.'
      });
    }

    // Delete profile first (if present), then member, then pull from leader
    const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
    await GroupMemberProfile.deleteOne({ groupMemberId: member._id });
    await GroupMember.deleteOne({ _id: member._id });
    await Leader.updateOne({ _id: leader._id }, { $pull: { members: member._id } });

    // Back to the list with a "deleted" flag
    return res.redirect(`/leader/${leaderId}/delete_group_member?deleted=1`);
  } catch (err) {
    console.error('Error deleting group member:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while deleting the group member.'
    });
  }
},

// Create Organization + attach to logged-in leader
createOrganization: async (req, res) => {
  try {
    // You’re storing a lightweight session snapshot in createLeader
    const leaderId = req.session?.user?.id;
    if (!leaderId) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Authorized',
        errorMessage: 'You must be logged in as a leader to create an organization.'
      });
    }

    const leader = await Leader.findById(leaderId);
    if (!leader) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'Leader not found.'
      });
    }

    // Guard: leaders who already have an org shouldn’t create a second one accidentally
    if (leader.organization && !leader.organizationOptOut) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Organization Exists',
        errorMessage: 'You already have an organization set up.'
      });
    }

    const { name, industry, domains } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).render('member_form_views/register_success', {
        layout: 'memberformlayout',
        title: 'Registration Successful',
        username: leader.username,
        user: leader,
        dashboardLink: "/dashboard/leader",
        csrfToken: req.csrfToken ? req.csrfToken() : null,
        orgErrorMessage: 'Organization name is required.'
      });
    }

    const cleanName = String(name).trim();
    const baseSlug = slugifyOrgName(cleanName);
    const slug = await buildUniqueSlug(baseSlug);
    const domainList = parseDomains(domains);

    const org = await Organization.create({
      name: cleanName,
      slug,
      industry: industry ? String(industry).trim() : undefined,
      domains: domainList
    });

    // Attach to leader
    leader.organization = org._id;
    leader.organizationName = org.name; // cache
    leader.organizationOptOut = false;
    await leader.save();

    // Optional: keep group profile consistent
    await GroupProfile.updateOne(
      { groupId: leader._id },
      { $set: { organization: org._id } }
    );

return res.redirect('/dashboard/leader/organization/success');
  } catch (err) {
    console.error('Error creating organization:', err);

    // Best-effort: show success page with an inline error so they don’t feel “kicked out”
    try {
      const leaderId = req.session?.user?.id;
      const leader = leaderId ? await Leader.findById(leaderId).lean() : null;

      return res.status(500).render('member_form_views/register_success', {
        layout: 'memberformlayout',
        title: 'Registration Successful',
        username: leader?.username || '',
        user: leader,
        dashboardLink: "/dashboard/leader",
        csrfToken: req.csrfToken ? req.csrfToken() : null,
        orgErrorMessage: 'An error occurred while creating your organization. Please try again.'
      });
    } catch {
      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Error',
        errorMessage: 'An unexpected error occurred while creating your organization.'
      });
    }
  }
},

showEditOrganizationForm: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Authorized',
        errorMessage: 'You must be logged in as a leader to edit an organization.'
      });
    }

    const leader = await Leader.findById(leaderId).populate('organization').lean();
    if (!leader || !leader.organization) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'No organization found to edit.'
      });
    }

    return res.render('member_form_views/edit_organization', {
      layout: 'memberformlayout',
      title: 'Edit Organization',
      user: leader,
      organization: leader.organization,
      csrfToken: req.csrfToken ? req.csrfToken() : null
    });
  } catch (err) {
    console.error('Error rendering edit organization form:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'An unexpected error occurred while loading the organization.'
    });
  }
},

updateOrganization: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Authorized',
        errorMessage: 'You must be logged in as a leader to update an organization.'
      });
    }

    const leader = await Leader.findById(leaderId);
    if (!leader || !leader.organization) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Not Found',
        errorMessage: 'No organization found to update.'
      });
    }

    const { name, industry, domains } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Validation Error',
        errorMessage: 'Organization name is required.'
      });
    }

    const cleanName = String(name).trim();
    const domainList = parseDomains(domains);

const org = await Organization.create({
  name: cleanName,
  slug,
  industry: industry ? String(industry).trim() : undefined,
  domains: domainList
});

// Attach to leader
leader.organization = org._id;
leader.organizationName = org.name; // cache
leader.organizationOptOut = false;
await leader.save();

// Optional: keep group profile consistent
await GroupProfile.updateOne(
  { groupId: leader._id },
  { $set: { organization: org._id } }
);

// ✅ store for success view + redirect to success notification
req.session.organizationJustCreatedName = org.name;
return res.redirect('/dashboard/leader/organization/success');

  } catch (err) {
    console.error('Error updating organization:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'An unexpected error occurred while updating the organization.'
    });
  }
},

requestJoinOrganization: async (req, res) => {
  try {
    const leaderId = req.session?.user?.id;
    if (!leaderId) return res.redirect('/dashboard/leader?msg=not-logged-in');

    const leader = await Leader.findById(leaderId).select('organization organizationOptOut').lean();
    if (!leader) return res.redirect('/dashboard/leader?msg=leader-not-found');

    // Optional guard: don’t allow request if already attached and not opted out
    if (leader.organization && !leader.organizationOptOut) {
      return res.redirect('/dashboard/leader?msg=already-has-org');
    }

    const raw = String(req.body.orgSlugOrName || '').trim().toLowerCase();
    if (!raw) return res.redirect('/dashboard/leader?msg=missing-org');

    // match by slug first, then by a loose name match
    const esc = raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const org = await Organization.findOne({
      $or: [{ slug: raw }, { name: new RegExp(esc, 'i') }]
    }).select('_id name slug').lean();

    if (!org) return res.redirect('/dashboard/leader?msg=org-not-found');

    await OrganizationJoinRequest.updateOne(
      { organization: org._id, leader: leaderId },
      { $setOnInsert: { status: 'pending', requestedAt: new Date() } },
      { upsert: true }
    );

    return res.redirect('/dashboard/leader?msg=join-request-sent');
  } catch (err) {
    console.error('requestJoinOrganization error:', err);
    return res.redirect('/dashboard/leader?msg=join-request-error');
  }
},


};


