// controllers/changemembershipController.js
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const CancelledMember = require('../models/member_models/cancelledmember');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

const MemberProfile = require('../models/profile_models/member_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupProfile = require('../models/profile_models/group_profile');
const { sendMail } = require('../utils/mailer');


const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

module.exports = {
  // Show form
  showChangeMembershipForm: (req, res) => {
    if (!req.user) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Unauthorized',
        errorMessage: 'You must be logged in to change your membership.'
      });
    }

    res.render('member_form_views/change_my_membership', {
      layout: 'memberformlayout',
      csrfToken: req.csrfToken(),
      user: req.user
    });
  },

  // Cancel Membership (Option A)
 cancelMembership: async (req, res) => {
  try {
    const user = req.user;
    const reason = (req.body.reason || '').trim();
    const mode = req.body.mode === 'immediate' ? 'immediate' : 'period_end';

    if (!user) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Unauthorized',
        errorMessage: 'You must be logged in to cancel your membership.'
      });
    }

    const ModelsByType = {
      member: Member,
      leader: Leader,
      group_member: GroupMember
    };

    const Model = ModelsByType[user.membershipType];
    const doc = Model ? await Model.findById(user._id) : null;

    if (!doc) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Account Not Found',
        errorMessage: 'We could not find your account.'
      });
    }

    let cancelAt = null;
    const subId = doc?.stripeSubscriptionId || null;

    const looksPaid =
      user.membershipType === 'leader' ||
      user.accessLevel === 'paid_individual' ||
      user.accessLevel === 'contributor_individual';

    if (looksPaid && !subId) {
      console.error('❌ Cancellation blocked: missing stripeSubscriptionId', {
        userId: user._id.toString(),
        membershipType: user.membershipType,
        accessLevel: user.accessLevel
      });

      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Cancellation Error',
        errorMessage: 'We could not locate your billing subscription. Please contact support before cancelling so billing is not left active.'
      });
    }

    // Cancel or schedule cancellation in Stripe first
    if (subId) {
      if (mode === 'immediate') {
        await stripe.subscriptions.cancel(subId);
        console.log('✅ Stripe subscription cancelled immediately:', subId);
      } else {
        const subscription = await stripe.subscriptions.update(subId, {
          cancel_at_period_end: true
        });

        if (subscription.cancel_at) {
          cancelAt = new Date(subscription.cancel_at * 1000);
        }

        console.log('✅ Stripe subscription set to cancel at period end:', {
          subId,
          cancelAt
        });
      }
    }

    // Archive cancellation after Stripe succeeds
    await new CancelledMember({
      originalId: user._id,
      name: user.name || user.groupLeaderName || user.username || 'Unknown User',
      username: user.username || '',
      email: user.email || user.groupLeaderEmail || '',
      membershipType: user.membershipType,
      accessLevel: user.accessLevel || null,
      wasLeader: user.membershipType === 'leader',
      reason
    }).save();

    // Update local account state
    if (mode === 'immediate') {
      doc.isActive = false;

      if ('subscriptionStatus' in doc) {
        doc.subscriptionStatus = 'canceled';
      }
      if ('paymentStatus' in doc) {
        doc.paymentStatus = 'cancelled';
      }
      if ('cancelAt' in doc) {
        doc.cancelAt = null;
      }

      if (user.membershipType === 'member' && 'accessLevel' in doc) {
        doc.accessLevel = 'free_individual';
      }
    } else {
      // Keep account active until Stripe actually ends it
      doc.isActive = true;

      if ('subscriptionStatus' in doc) {
        doc.subscriptionStatus = 'cancel_at_period_end';
      }
      if ('paymentStatus' in doc) {
        doc.paymentStatus = 'paid';
      }
      if ('cancelAt' in doc) {
        doc.cancelAt = cancelAt || null;
      }
    }

    await doc.save();

    // Leader cascade only for immediate cancellation
    if (user.membershipType === 'leader' && mode === 'immediate') {
      await GroupMember.updateMany(
        { groupId: doc._id },
        { $set: { isActive: false } }
      );
    }

    // Email notification to Twennie
    try {
      const cancelingName = user.name || user.groupLeaderName || user.username || 'Unknown User';
      const cancelingEmail = user.email || user.groupLeaderEmail || 'Unknown Email';

      await sendMail({
        to: 'info@twennie.com',
        subject: `Twennie membership cancellation: ${cancelingName}`,
        text: `
A membership cancellation was submitted on Twennie.

Name: ${cancelingName}
Email: ${cancelingEmail}
Membership Type: ${user.membershipType}
Access Level: ${user.accessLevel || 'N/A'}
Cancellation Mode: ${mode}
Subscription ID: ${subId || 'None found'}
Effective Cancel Date: ${cancelAt ? cancelAt.toISOString() : 'Immediate or not provided'}
Reason: ${reason || 'No reason provided'}
        `.trim(),
        html: `
          <p>A membership cancellation was submitted on Twennie.</p>
          <p><strong>Name:</strong> ${cancelingName}</p>
          <p><strong>Email:</strong> ${cancelingEmail}</p>
          <p><strong>Membership Type:</strong> ${user.membershipType}</p>
          <p><strong>Access Level:</strong> ${user.accessLevel || 'N/A'}</p>
          <p><strong>Cancellation Mode:</strong> ${mode}</p>
          <p><strong>Subscription ID:</strong> ${subId || 'None found'}</p>
          <p><strong>Effective Cancel Date:</strong> ${cancelAt ? cancelAt.toLocaleString('en-CA') : 'Immediate or not provided'}</p>
          <p><strong>Reason:</strong><br>${(reason || 'No reason provided').replace(/\n/g, '<br>')}</p>
        `
      });

      console.log('✅ Cancellation notification email sent.');
    } catch (mailErr) {
      console.error('❌ Failed to send cancellation notification email:', mailErr);
    }

    req.logout?.(() => {});
    req.session.destroy(() => {
      return res.render('member_form_views/cancel_success', {
        layout: 'memberformlayout',
        title: mode === 'immediate' ? 'Subscription Cancelled' : 'Cancellation Scheduled',
        when: mode === 'immediate' ? 'cancelled' : 'cancellation scheduled',
        cancelAt: cancelAt ? cancelAt.toLocaleString('en-CA') : null,
        subscriptionId: subId || null,
        dashboardPath: '/',
        supportEmail: 'info@twennie.com'
      });
    });
  } catch (err) {
    console.error('❌ Error cancelling membership:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error Cancelling Membership',
      errorMessage: 'An error occurred while cancelling your membership. Please try again.'
    });
  }
},

  // Confirm success (used by some change flows)
  changeSuccess: (req, res) => {
    const username = req.session.user?.username || 'User';
    const membershipType = req.session.user?.membershipType;

    const dashboardLink =
      membershipType === 'leader'
        ? '/dashboard/leader'
        : membershipType === 'group_member'
          ? '/dashboard/group'
          : '/dashboard/member';

    res.render('member_form_views/change_success', {
      layout: 'memberformlayout',
      title: 'Membership Updated',
      username,
      dashboardLink
    });
  },

  // Upgrade to Free Membership
// Upgrade to Free Membership
changeToFree: async (req, res) => {
  try {
    const user = req.user;

    if (!user || user.membershipType !== 'member') {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Access Denied',
        errorMessage: 'Only members can switch to free membership.'
      });
    }

    const freshMember = await Member.findById(user._id);
    if (!freshMember) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Account Not Found',
        errorMessage: 'We could not find your account.'
      });
    }

    // Do not allow a paid member to silently downgrade locally
    // while Stripe billing may still be active.
    const hasStripeSubscription = !!freshMember.stripeSubscriptionId;
    const looksPaid =
      freshMember.accessLevel === 'paid_individual' ||
      freshMember.subscriptionStatus === 'active' ||
      freshMember.subscriptionStatus === 'cancel_at_period_end' ||
      freshMember.paymentStatus === 'paid';

    if (hasStripeSubscription || looksPaid) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Cancellation Required',
        errorMessage: 'This account has an active or recent paid subscription. Please use the cancellation option first so billing is properly stopped before switching to free membership.'
      });
    }

    freshMember.accessLevel = 'free_individual';
    freshMember.membershipType = 'member';
    freshMember.subscriptionStatus = 'pending';
    freshMember.paymentStatus = 'pending';
    freshMember.cancelAt = null;

    await freshMember.save();

    if (req.session.user) {
      req.session.user.membershipType = 'member';
      req.session.user.accessLevel = 'free_individual';
    }

    return res.redirect('/change_membership/success');
  } catch (err) {
    console.error('❌ Error changing to free membership:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error',
      errorMessage: 'Unable to update your membership. Please try again.'
    });
  }
},

  // Upgrade to Paid Individual (Stripe)
// Upgrade to Paid Individual (Stripe)
changeToIndividual: async (req, res) => {
  try {
    const user = req.user;

    if (!user || user.membershipType !== 'member') {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Access Denied',
        errorMessage: 'Only members can become individual members.'
      });
    }

    const freshMember = await Member.findById(user._id);
    if (!freshMember) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Account Not Found',
        errorMessage: 'We could not find your account.'
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: freshMember.email,
      line_items: [
        {
          price_data: {
            currency: 'cad',
            unit_amount: 1700,
            recurring: { interval: 'month' },
            product_data: { name: 'Twennie Paid Individual Membership' }
          },
          quantity: 1
        }
      ],
      automatic_tax: { enabled: true },
      billing_address_collection: 'required',
      metadata: {
        memberId: freshMember._id.toString(),
        membershipType: 'member',
        accessLevel: 'paid_individual'
      },
      subscription_data: {
        metadata: {
          memberId: freshMember._id.toString(),
          membershipType: 'member',
          accessLevel: 'paid_individual'
        }
      },
      success_url: `${baseUrl}/change_membership/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/change_membership`
    });

    return res.redirect(303, session.url);

  } catch (err) {
    console.error('❌ Error starting Stripe checkout for individual upgrade:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Payment Error',
      errorMessage: 'Unable to start checkout. Please try again.'
    });
  }
},

  // Upgrade to Leader
// Upgrade to Leader
changeToLeader: async (req, res) => {
  try {
    const user = req.user;

    if (!user || user.membershipType !== 'member') {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Access Denied',
        errorMessage: 'Only members can become leaders from this form.'
      });
    }

    const freshMember = await Member.findById(user._id);
    if (!freshMember) {
      return res.status(404).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Account Not Found',
        errorMessage: 'We could not find your account.'
      });
    }

    const {
      groupName,
      groupLeaderName,
      professionalTitle,
      industry,
      username,
      groupLeaderEmail,
      password,
      groupSize,
      registration_code,
      organizationOptOut,
      line1,
      line2,
      city,
      province,
      postalCode,
      country,
      members
    } = req.body;

    // Normalize submitted members (array or JSON string)
    let memberList = [];
    if (Array.isArray(members)) {
      memberList = members;
    } else if (typeof members === 'string' && members.trim()) {
      try {
        const parsed = JSON.parse(members);
        memberList = Array.isArray(parsed) ? parsed : [];
      } catch {
        memberList = [];
      }
    }

    // Clean out empty rows
    memberList = memberList
      .map((m) => ({
        name: (m?.name || '').trim(),
        email: (m?.email || '').trim().toLowerCase()
      }))
      .filter((m) => m.name && m.email);

    const parsedGroupSize = parseInt(groupSize, 10);
    if (!Number.isFinite(parsedGroupSize) || parsedGroupSize < 2 || parsedGroupSize > 10) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Invalid Group Size',
        errorMessage: 'Group size must be between 2 and 10.'
      });
    }

    // Keep this consistent with your main leader registration flow:
    // the submitted member list represents group members, and Stripe bills leader + submitted members.
    if (memberList.length !== parsedGroupSize) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Group Size Mismatch',
        errorMessage: `You selected ${parsedGroupSize} members, but submitted ${memberList.length} member records. Please make them match.`
      });
    }

    // Check for duplicate member emails inside the submitted group
    const submittedEmails = memberList.map((m) => m.email);
    const duplicateSubmittedEmails = submittedEmails.filter(
      (email, index) => submittedEmails.indexOf(email) !== index
    );

    if (duplicateSubmittedEmails.length > 0) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Duplicate Member Emails',
        errorMessage: 'Each group member must have a unique email address.'
      });
    }

    // Basic uniqueness checks before creating anything
    const existingLeader = await Leader.findOne({
      $or: [
        { username: username.trim() },
        { groupLeaderEmail: groupLeaderEmail.trim().toLowerCase() },
        { registration_code: registration_code.trim() }
      ]
    }).lean();

    if (existingLeader) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Duplicate Leader Details',
        errorMessage: 'That username, email, or registration code is already in use.'
      });
    }

    const existingGroupMember = await GroupMember.findOne({
      email: { $in: submittedEmails }
    }).lean();

    if (existingGroupMember) {
      return res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Member Already Exists',
        errorMessage: 'One of the submitted group member email addresses is already in use.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newLeader = new Leader({
      groupName: groupName.trim(),
      groupLeaderName: groupLeaderName.trim(),
      professionalTitle: professionalTitle.trim(),

      // Current schema expects organization fields like this
      organization: null,
      organizationOptOut: organizationOptOut === 'true' || organizationOptOut === true || organizationOptOut === 'on',
      organizationName: '',

      industry: industry.trim(),
      username: username.trim(),
      groupLeaderEmail: groupLeaderEmail.trim().toLowerCase(),
      password: hashedPassword,
      groupSize: parsedGroupSize,
      registration_code: registration_code.trim(),

      billingAddress: {
        line1: line1?.trim() || '',
        line2: line2?.trim() || '',
        city: city?.trim() || '',
        province: province?.trim() || '',
        postalCode: postalCode?.trim() || '',
        country: country?.trim() || 'CA'
      },

      isActive: true,
      membershipType: 'leader',
      accessLevel: 'leader',
      paymentStatus: 'pending',
      subscriptionStatus: 'pending',
      members: []
    });

    await newLeader.save();

    // Create group members now so the upgraded leader flow matches the dedicated leader flow
    const createdGroupMembers = [];
    for (let i = 0; i < memberList.length; i += 1) {
      const m = memberList[i];

      const groupMember = new GroupMember({
        leader: newLeader._id,
        groupId: newLeader._id,
        groupName: newLeader.groupName,
        organization: newLeader.organization || null,
        organizationName: newLeader.organizationName || '',
        name: m.name,
        email: m.email,
        username: `member_${i}_${newLeader.groupName.toLowerCase().replace(/\s+/g, '_')}`,
        password: await bcrypt.hash('defaultPassword123', 10)
      });

      const savedGroupMember = await groupMember.save();
      createdGroupMembers.push(savedGroupMember._id);
    }

    if (createdGroupMembers.length > 0) {
      newLeader.members = createdGroupMembers;
      await newLeader.save();
    }

    // Create Stripe customer first for consistency with the main leader flow
    const seats = 1 + memberList.length; // leader + group members

    const customer = await stripe.customers.create({
      email: newLeader.groupLeaderEmail,
      name: newLeader.groupLeaderName,
      metadata: {
        leaderId: newLeader._id.toString(),
        originalMemberId: freshMember._id.toString(),
        groupName: newLeader.groupName,
        seats: String(seats),
        members: String(memberList.length)
      }
    });

    newLeader.stripeCustomerId = customer.id;
    await newLeader.save();

    // Deactivate original individual member record
    await Member.findByIdAndUpdate(freshMember._id, { isActive: false });

    // Create leader profile from existing member profile if available
const existingMemberProfile = await MemberProfile.findOne({ memberId: user._id }).lean();

await LeaderProfile.findOneAndUpdate(
  { leaderId: newLeader._id },
  {
    $setOnInsert: {
      leaderId: newLeader._id,
      name: existingMemberProfile?.name || newLeader.groupLeaderName,
      professionalTitle: existingMemberProfile?.professionalTitle || newLeader.professionalTitle,
      profileImage: existingMemberProfile?.profileImage || '/images/default-avatar.png',
      biography: existingMemberProfile?.biography || '',
      goals: existingMemberProfile?.goals || '',
      groupLeadershipGoals: '',
      topics: existingMemberProfile?.topics || {}
    }
  },
  { upsert: true, new: true, setDefaultsOnInsert: true }
);

// Ensure group profile also exists
await GroupProfile.findOneAndUpdate(
  { groupId: newLeader._id },
  {
    $setOnInsert: {
      groupId: newLeader._id,
      groupName: newLeader.groupName,
      groupLeaderName: newLeader.groupLeaderName,
      organization: newLeader.organization || null,
      groupSize: newLeader.groupSize,
      groupGoals: '',
      groupTopics: existingMemberProfile?.topics || {},
      members: [],
      groupImage: '/images/default-group.png'
    }
  },
  { upsert: true, new: true, setDefaultsOnInsert: true }
);

    req.session.user = {
      id: newLeader._id.toString(),
      username: newLeader.username,
      membershipType: 'leader',
      accessLevel: 'leader',
      email: newLeader.groupLeaderEmail
    };

    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price_data: {
            currency: 'cad',
            unit_amount: 1700,
            recurring: { interval: 'month' },
            product_data: { name: 'Twennie Group Leader Membership' }
          },
          quantity: seats
        }
      ],
      automatic_tax: { enabled: true },
      billing_address_collection: 'required',
      customer_update: { address: 'auto', name: 'auto' },

      metadata: {
        leaderId: newLeader._id.toString(),
        originalMemberId: freshMember._id.toString(),
        membershipType: 'leader',
        accessLevel: 'leader',
        groupName: newLeader.groupName,
        seats: String(seats),
        members: String(memberList.length)
      },

      subscription_data: {
        metadata: {
          leaderId: newLeader._id.toString(),
          originalMemberId: freshMember._id.toString(),
          membershipType: 'leader',
          accessLevel: 'leader',
          groupName: newLeader.groupName,
          seats: String(seats),
          members: String(memberList.length)
        }
      },

      success_url: `${baseUrl}/change_membership/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/change_membership`
    });

    return res.redirect(303, session.url);

  } catch (err) {
    console.error('❌ Error changing to leader:', err);
    return res.status(500).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'Error Changing Membership',
      errorMessage: 'An error occurred while registering you as a group leader. Please try again.'
    });
  }
},
};



