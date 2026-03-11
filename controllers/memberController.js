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
  // --- helpers kept inside the function for locality ---
  const ALLOWED_ACCESS = ['free_individual', 'contributor_individual', 'paid_individual'];

  function normalizeAccessLevel(raw) {
    const v = Array.isArray(raw) ? raw[raw.length - 1] : raw;
    const str = (v || '').toString().trim();
    if (['free', 'free_individual'].includes(str)) return 'free_individual';
    if (['contributor', 'contributor_individual'].includes(str)) return 'contributor_individual';
    if (['paid', 'paid_individual'].includes(str)) return 'paid_individual';
    return 'free_individual'; // safe default
  }

  try {
    // Destructure from body
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
  line1,
  line2,
  city,
  province,
  postalCode,
  country,
  accessLevel: rawAccessLevel,
  redirectTarget,
} = req.body;

    // Normalize access level defensively (handles arrays & aliases)
    const accessLevel = normalizeAccessLevel(rawAccessLevel);

    // Log a minimal trace (don’t log password)
    console.log('Received registration data:', {
      name,
      username,
      email,
      accessLevel,
      redirectTarget,
    });

    // Run your existing validator (coerce the access level for it too)
    const bodyForValidation = { ...req.body, accessLevel };
    const errors = validateMemberData(bodyForValidation);
    if (errors.length > 0) {
      return res.status(400).render('member_form_views/member_form', {
        layout: 'memberformlayout',
        title: 'Individual Membership Form',
        errors,
        data: bodyForValidation,
      });
    }

    // Uniqueness check on username OR email
const existing = await Member.findOne({
  $or: [
    { username: normalizedUsername },
    { email: normalizedEmail }
  ]
}).lean();


    if (existing) {
      return res.status(400).render('member_form_views/member_form', {
        layout: 'memberformlayout',
        title: 'Username or Email Exists',
        errorMessage: 'That username or email is already registered.',
        data: bodyForValidation,
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Build topics only if present
    const topics =
      topic1 || topic2 || topic3 ? { topic1: topic1 || '', topic2: topic2 || '', topic3: topic3 || '' } : undefined;

    // Create and save Member
const newMember = new Member({
  name,
  professionalTitle,
  organization,
  industry,
  username: normalizedUsername,
  email: normalizedEmail,
  password: hashedPassword,
  topics,
  billingAddress: {
    line1: line1?.trim() || '',
    line2: line2?.trim() || '',
    city: city?.trim() || '',
    province: province?.trim() || '',
    postalCode: postalCode?.trim() || '',
    country: country?.trim() || 'CA'
  },
  accessLevel,
  membershipType: 'member',
});

    try {
      await newMember.save();
    } catch (e) {
      // Friendly duplicate-key handling
      if (e && e.code === 11000) {
        const fields = Object.keys(e.keyPattern || {});
        const msg =
          fields.length > 0
            ? `The value for ${fields.join(', ')} is already in use. Please choose another.`
            : 'That username or email is already registered.';
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Individual Membership Form',
          errorMessage: msg,
          data: bodyForValidation,
        });
      }
      throw e;
    }

    console.log('✅ Member saved:', newMember._id.toString());

    // Create a Member Profile
    const memberProfile = new MemberProfile({
      memberId: newMember._id,
      name: newMember.name,
      professionalTitle: newMember.professionalTitle,
      profileImage: '/images/default-avatar.png',
      biography: '',
      goals: '',
      topics,
    });
    await memberProfile.save();
    console.log(`✅ Member Profile Created: ${memberProfile._id}`);

    // Lightweight session snapshot (OK to keep; your auth flow may set req.user after login)
    req.session.user = {
      id: newMember._id.toString(),
      username: newMember.username,
      membershipType: newMember.membershipType,
      accessLevel: newMember.accessLevel,
    };

    // Paid plan → Stripe Checkout
    if (accessLevel === 'paid_individual') {
      const successBase = getSuccessBase(req);

const session = await stripe.checkout.sessions.create({
  mode: 'subscription',
  payment_method_types: ['card'],
  line_items: [
    {
      price_data: {
        currency: 'cad',
        unit_amount: 1700,
        recurring: { interval: 'month' },
        product_data: { name: 'Twennie Paid Individual Membership' },
      },
      quantity: 1,
    },
  ],
  automatic_tax: { enabled: true },
  billing_address_collection: 'required',
  customer_email: email,

  metadata: {
    memberId: newMember._id.toString(),
    accessLevel: 'paid_individual',
    membershipType: 'member',
  },

  subscription_data: {
    metadata: {
      memberId: newMember._id.toString(),
      accessLevel: 'paid_individual',
      membershipType: 'member',
    },
  },

  success_url: `${successBase}/member/payment/success?session_id={CHECKOUT_SESSION_ID}`,
  cancel_url: `${successBase}/member/payment/cancel`,
});

      return res.redirect(303, session.url);
    }

    // Free or Contributor → immediate success page
    return res.render('member_form_views/register_success', {
      layout: 'memberformlayout',
      title: 'Registration Successful',
      username: newMember.username,
      user: newMember,
      dashboardLink: '/dashboard/member',
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
}




