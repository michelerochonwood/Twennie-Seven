const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

module.exports = (passport) => {

  // ✅ Local Strategy for email/password login
  passport.use(new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    },
    async (req, email, password, done) => {
      try {
        const normalizedEmail = email.toLowerCase();
        const { membershipType } = req.body;
        let user;

        if (membershipType === 'member') {
          user = await Member.findOne({ email: normalizedEmail });
        } else if (membershipType === 'leader') {
          user = await Leader.findOne({ groupLeaderEmail: normalizedEmail });
        } else if (membershipType === 'group_member') {
          user = await GroupMember.findOne({ email: normalizedEmail });
        } else {
          return done(null, false, { message: 'Invalid membership type.' });
        }

        if (!user) {
          return done(null, false, { message: 'No user found with that email.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: 'Incorrect email or password.' });
        }

        console.log("✅ LocalStrategy authenticated:", {
          id: user._id?.toString(),
          email: user.email || user.groupLeaderEmail,
          type: membershipType
        });

        return done(null, user);

      } catch (err) {
        console.error("❌ LocalStrategy error:", err);
        return done(err);
      }
    }
  ));

  // ✅ Google OAuth2 Strategy (for Members only)
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    proxy: true
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await Member.findOne({ googleId: profile.id });

      if (!user) {
        user = new Member({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          avatar: profile.photos[0].value
        });
        await user.save();
      }

      return done(null, user);

    } catch (err) {
      console.error("❌ GoogleStrategy error:", err);
      return done(err, null);
    }
  }));

  // ✅ Serialize user into session
  passport.serializeUser((user, done) => {
    console.log("🧠 serializeUser received:", user);

    if (!user || (!user._id && !user.id)) {
      console.error("❌ Cannot serialize user. Missing ID. User:", user);
      return done(new Error("Cannot serialize user without a valid ID"));
    }

    const userId = user._id || user.id;
    return done(null, userId.toString());
  });

  // ✅ Deserialize user from session (Mongoose docs preserved)
  passport.deserializeUser(async (id, done) => {
    try {
      const user =
        (await Member.findById(id)) ||
        (await Leader.findById(id)) ||
        (await GroupMember.findById(id));

      if (!user) {
        console.warn("⚠️ deserializeUser: No user found with ID:", id);
        return done(null, false);
      }

      return done(null, user);

    } catch (err) {
      console.error("❌ deserializeUser error:", err);
      return done(err, false);
    }
  });

};






