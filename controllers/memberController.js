// controllers/memberController.js
const Member = require('../models/member_models/member');
const MemberProfile = require('../models/profile_models/member_profile');
const { validateMemberData } = require('../utils/validateMember');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// In production, set BASE_URL=https://www.twennie.com
const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

module.exports = {
  // Render Individual Membership Form
  showMemberForm: (req, res) => {
    res.render('member_form_views/member_form', {
      layout: 'memberformlayout',
      title: 'Individual Membership Form',
      csrfToken: req.csrfToken?.(),
    });
  },

  // Create new Individual Member (free or paid)
  createMember: async (req, res) => {
    try {
      const {
        name,
        professionalTitle,
        organization,
        industry,
        username,
        email,
        password,
        accessLevel // expected: 'free_individual' | 'paid_individual' | 'contributor_individual' (if you use that)
      } = req.body;

      // 1) Validate form payload
      const errors = validateMemberData(req.body);
      if (errors.length > 0) {
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Individual Membership Form',
          errors,
          data: req.body
        });
      }

      // 2) Uniqueness check (username OR email must be unique)
      const existing = await Member.findOne({ $or: [{ username }, { email }] });
      if (existing) {
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Username or Email Exists',
          errorMessage: 'That username or email is already registered.',
          data: req.body
        });
      }

      // 3) Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // 4) Create the Member (NO topics at signup)
      const newMember = new Member({
        name,
        professionalTitle,
        organization,
        industry,
        username,
        email,
        password: hashedPassword,
        membershipType: 'member',
        accessLevel: accessLevel || 'free_individual'
        // topics removed — they can be added later via profile
      });

      await newMember.save();
      console.log('✅ Member saved:', newMember._id.toString());

      // 5) Create a basic MemberProfile (NO topics initially)
      const memberProfile = new MemberProfile({
        memberId: newMember._id,
        name: newMember.name,
        professionalTitle: newMember.professionalTitle,
        profileImage: '/images/default-avatar.png',
        biography: '',
        goals: ''
      });
      await memberProfile.save();
      console.log(`✅ Member Profile Created: ${memberProfile._id}`);

      // 6) Session snapshot (optional; Passport login can happen separately)
      req.session.user = {
        id: newMember._id,
        username: newMember.username,
        membershipType: newMember.membershipType,
        accessLevel: newMember.accessLevel
      };

      // 7) Paid individual → Stripe Checkout
      if (accessLevel === 'paid_individual') {
        // One seat @ $17 CAD/month
        const session = await stripe.checkout.sessions.create({
          mode: 'subscription',
          payment_method_types: ['card'],

          // Use a one-off price (as you currently do) or switch to a reusable Price ID later
          line_items: [{
            price_data: {
              currency: 'cad',
              unit_amount: 1700,
              recurring: { interval: 'month' },
              product_data: { name: 'Twennie Paid Individual Membership' }
            },
            quantity: 1
          }],

          // Let Checkout collect + save address for tax
          automatic_tax: { enabled: true },
          billing_address_collection: 'required',

          // Helpful metadata on the subscription for your success handler/webhooks
          subscription_data: {
            metadata: {
              memberId: newMember._id.toString(),
              memberEmail: email,
              membershipType: 'member',
              accessLevel: 'paid_individual'
            }
          },

          // Use customer_email so Checkout creates a Customer for them
          customer_email: email,

          // IMPORTANT: include the session_id in the success URL
          success_url: `${baseUrl}/member/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${baseUrl}/member/payment/cancel`
        });

        return res.redirect(303, session.url);
      }

      // 8) Free/contributor flow → immediate success page
      return res.render('member_form_views/register_success', {
        layout: 'memberformlayout',
        title: 'Registration Successful',
        username: newMember.username,
        user: newMember,
        dashboardLink: '/dashboard/member'
      });

    } catch (err) {
      console.error('❌ Error creating member:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Registration Error',
        errorMessage: 'An error occurred while creating the member. Please try again.'
      });
    }
  }
};




