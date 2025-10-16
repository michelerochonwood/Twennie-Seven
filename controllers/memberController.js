// controllers/memberController.js
const Member = require('../models/member_models/member');
const MemberProfile = require('../models/profile_models/member_profile');
const { validateMemberData } = require('../utils/validateMember');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Prefer configured BASE_URL; otherwise derive from request (proxy aware)
function getSuccessBase(req) {
  const env = process.env.BASE_URL;
  if (env && /^https?:\/\//.test(env)) return env.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https');
  const host  = (req.headers['x-forwarded-host']  || req.get('host'));
  return `${proto}://${host}`;
}

module.exports = {
  showMemberForm: (req, res) => {
    res.render('member_form_views/member_form', {
      layout: 'memberformlayout',
      title: 'Individual Membership Form',
      csrfToken: req.csrfToken?.(),
    });
  },

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
        topic1,
        topic2,
        topic3,
        accessLevel
      } = req.body;

      console.log('Received registration data:', { name, username, email, accessLevel });

      // 1) Validate form payload
      const errors = validateMemberData(req.body);
      if (errors.length > 0) {
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Individual Membership Form',
          errors,
          data: req.body,
        });
      }

      // 2) Uniqueness check (username OR email)
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

      // 4) Create Member (keeps topics since schema currently supports them)
      const newMember = new Member({
        name,
        professionalTitle,
        organization,
        industry,
        username,
        email,
        password: hashedPassword,
        topics: (topic1 || topic2 || topic3) ? { topic1, topic2, topic3 } : undefined,
        accessLevel: accessLevel || 'free_individual',
        membershipType: 'member',
      });

      try {
        await newMember.save();
      } catch (e) {
        // Friendly duplicate-key handling
        if (e && e.code === 11000) {
          const fields = Object.keys(e.keyPattern || {});
          const msg = fields.length
            ? `The value for ${fields.join(', ')} is already in use. Please choose another.`
            : 'That username or email is already registered.';
          return res.status(400).render('member_form_views/member_form', {
            layout: 'memberformlayout',
            title: 'Individual Membership Form',
            errorMessage: msg,
            data: req.body
          });
        }
        throw e;
      }
      console.log('✅ Member saved:', newMember._id.toString());

      // 5) Create Member Profile
      const memberProfile = new MemberProfile({
        memberId: newMember._id,
        name: newMember.name,
        professionalTitle: newMember.professionalTitle,
        profileImage: "/images/default-avatar.png",
        biography: "",
        goals: "",
        topics: (topic1 || topic2 || topic3)
          ? { topic1: topic1 || "", topic2: topic2 || "", topic3: topic3 || "" }
          : undefined,
      });
      await memberProfile.save();
      console.log(`✅ Member Profile Created: ${memberProfile._id}`);

      // 6) Lightweight session snapshot
      req.session.user = {
        id: newMember._id.toString(),
        username: newMember.username,
        membershipType: newMember.membershipType,
        accessLevel: newMember.accessLevel
      };

      // 7) Stripe Checkout for paid individuals
      if (accessLevel === 'paid_individual') {
        const successBase = getSuccessBase(req);

        const session = await stripe.checkout.sessions.create({
          mode: 'subscription',
          payment_method_types: ['card'],
          line_items: [{
            price_data: {
              currency: 'cad',
              unit_amount: 1700,
              recurring: { interval: 'month' },
              product_data: { name: 'Twennie Paid Individual Membership' }
            },
            quantity: 1
          }],

          // Stripe Tax: let Checkout collect + save address
          automatic_tax: { enabled: true },
          billing_address_collection: 'required',
          customer_email: email,
          // helpful metadata for the success handler
          subscription_data: {
            metadata: {
              memberId: newMember._id.toString(),
              accessLevel: 'paid_individual',
              membershipType: 'member'
            }
          },
          // New success URL with session_id; use host/proto fallback if BASE_URL missing
          success_url: `${successBase}/member/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url:  `${successBase}/member/payment/cancel`
        });

        return res.redirect(303, session.url);
      }

      // 8) Free/contributor flow → immediate success page
      return res.render("member_form_views/register_success", {
        layout: "memberformlayout",
        title: "Registration Successful",
        username: newMember.username,
        user: newMember,
        dashboardLink: "/dashboard/member"
      });

    } catch (err) {
      console.error('❌ Error creating member:', err);
      return res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Registration Error',
        errorMessage: 'An error occurred while creating the member. Please try again.',
      });
    }
  }
};




