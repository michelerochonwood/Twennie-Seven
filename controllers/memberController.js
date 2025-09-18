const Member = require('../models/member_models/member');
const MemberProfile = require('../models/profile_models/member_profile');
const { validateMemberData } = require('../utils/validateMember');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

module.exports = {
  showMemberForm: (req, res) => {
    res.render('member_form_views/member_form', {
      layout: 'memberformlayout',
      title: 'Individual Membership Form',
      csrfToken: req.csrfToken(),
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

      const errors = validateMemberData(req.body);
      if (errors.length > 0) {
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Individual Membership Form',
          errors,
          data: req.body,
        });
      }

      const existing = await Member.findOne({ $or: [{ username }, { email }] });
      if (existing) {
        return res.status(400).render('member_form_views/member_form', {
          layout: 'memberformlayout',
          title: 'Username or Email Exists',
          errorMessage: 'That username or email is already registered.',
          data: req.body
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newMember = new Member({
        name,
        professionalTitle,
        organization,
        industry,
        username,
        email,
        password: hashedPassword,
        topics: { topic1, topic2, topic3 },
        accessLevel: accessLevel || 'free_individual',
        membershipType: 'member',
      });

      await newMember.save();
      console.log('✅ Member saved:', newMember._id);

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

      req.session.user = {
        id: newMember._id,
        username: newMember.username,
        membershipType: newMember.membershipType,
        accessLevel: newMember.accessLevel
      };

      if (accessLevel === 'paid_individual') {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [{
            price_data: {
              currency: 'cad',
              unit_amount: 1700,
              recurring: { interval: 'month' },
              product_data: { name: 'Twennie Paid Individual Membership' }
            },
            quantity: 1
          }],
          billing_address_collection: 'required',
          customer_email: email,
          success_url: `${baseUrl}/member/payment/success`,
          cancel_url: `${baseUrl}/member/payment/cancel`
        });

        return res.redirect(303, session.url);
      }

      res.render("member_form_views/register_success", {
        layout: "memberformlayout",
        title: "Registration Successful",
        username: newMember.username,
        user: newMember,
        dashboardLink: "/dashboard/member"
      });

    } catch (err) {
      console.error('❌ Error creating member:', err);
      res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Registration Error',
        errorMessage: 'An error occurred while creating the member. Please try again.',
      });
    }
  }
};



