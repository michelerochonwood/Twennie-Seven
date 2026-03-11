// controllers/changemembershipController.js
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const CancelledMember = require('../models/member_models/cancelledmember');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

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
    const reason = req.body.reason || '';
    const mode = req.body.mode === 'immediate' ? 'immediate' : 'period_end';

    if (!user) {
      return res.status(401).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Unauthorized',
        errorMessage: 'You must be logged in to cancel your membership.'
      });
    }

    const ModelsByType = { member: Member, leader: Leader, group_member: GroupMember };
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

    // If this is a paid account and we have no Stripe subscription id, stop here.
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

    // Cancel / schedule cancel in Stripe first
    if (subId) {
      if (mode === 'immediate') {
        await stripe.subscriptions.cancel(subId);
        console.log('✅ Stripe subscription cancelled immediately:', subId);
      } else {
        const s = await stripe.subscriptions.update(subId, {
          cancel_at_period_end: true
        });

        if (s.cancel_at) {
          cancelAt = new Date(s.cancel_at * 1000);
        }

        console.log('✅ Stripe subscription set to cancel at period end:', {
          subId,
          cancelAt
        });
      }
    }

    // Archive the cancellation only after Stripe succeeds
    await new CancelledMember({
      originalId: user._id,
      name: user.name || user.groupLeaderName,
      username: user.username,
      email: user.email || user.groupLeaderEmail,
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

      // Optional: downgrade individual paid members immediately
      if (user.membershipType === 'member' && 'accessLevel' in doc) {
        doc.accessLevel = 'free_individual';
      }
    } else {
      // period_end: keep account active until Stripe actually ends it
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

    req.logout?.(() => {});
    req.session.destroy(() => {
      res.render('member_form_views/cancel_success', {
        layout: 'memberformlayout',
        title: (mode === 'immediate') ? 'Subscription Cancelled' : 'Cancellation Scheduled',
        when: (mode === 'immediate') ? 'cancelled' : 'cancellation scheduled',
        cancelAt: cancelAt ? cancelAt.toLocaleString('en-CA') : null,
        subscriptionId: subId || null,
        dashboardPath: '/',
        supportEmail: 'info@twennie.com'
      });
    });

  } catch (err) {
    console.error('❌ Error cancelling membership:', err);
    res.status(500).render('member_form_views/error', {
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

      await Member.findByIdAndUpdate(user._id, {
        accessLevel: 'free_individual',
        membershipType: 'member'
      });

      req.session.user.membershipType = 'member';
      req.session.user.accessLevel = 'free_individual';

      res.redirect('/change_membership/success');
    } catch (err) {
      console.error('❌ Error changing to free membership:', err);
      res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Error',
        errorMessage: 'Unable to update your membership. Please try again.'
      });
    }
  },

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

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'subscription',
        customer_email: user.email,
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
        metadata: { memberId: user._id.toString() },
        success_url: `${baseUrl}/change_membership/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${baseUrl}/change_membership`
      });

      return res.redirect(303, session.url);

    } catch (err) {
      console.error('❌ Error starting Stripe checkout:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Payment Error',
        errorMessage: 'Unable to start checkout. Please try again.'
      });
    }
  },

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

      const {
        groupName,
        groupLeaderName,
        professionalTitle,
        organization,
        industry,
        username,
        groupLeaderEmail,
        password,
        groupSize,
        registration_code
      } = req.body;

      const hashedPassword = await bcrypt.hash(password, 10);

      const newLeader = new Leader({
        groupName,
        groupLeaderName,
        professionalTitle,
        organization,
        industry,
        username,
        groupLeaderEmail,
        password: hashedPassword,
        groupSize,
        registration_code,
        isActive: true,
        membershipType: 'leader',
        accessLevel: 'leader',
        paymentStatus: 'pending'
      });

      await newLeader.save();
      await Member.findByIdAndUpdate(user._id, { isActive: false });

      req.session.user = {
        _id: newLeader._id,
        membershipType: 'leader',
        accessLevel: 'leader',
        username: newLeader.username,
        email: newLeader.groupLeaderEmail
      };

      // Redirect to Stripe Checkout (quantity = members only)
      const quantity = parseInt(groupSize, 10) || 1;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'subscription',
        line_items: [
          {
            price_data: {
              currency: 'cad',
              unit_amount: 1700, // $17 CAD per user
              recurring: { interval: 'month' },
              product_data: { name: 'Twennie Group Leader Membership' }
            },
            quantity
          }
        ],
        billing_address_collection: 'required',
        customer_email: groupLeaderEmail,
        metadata: {
          leaderId: newLeader._id.toString(),
          originalMemberId: user._id.toString()
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
  }
};



