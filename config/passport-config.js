const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

module.exports = (passport) => {

  // ✅ Local Strategy for email/password login
// ✅ Google OAuth2 Strategy (Member, Leader, GroupMember)
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    proxy: true
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = (profile.emails?.[0]?.value || '').toLowerCase();
      const googleId = profile.id;
      const avatar = profile.photos?.[0]?.value || null;
      const displayName = profile.displayName || null;

      if (!email) {
        return done(null, false, { message: 'Google account did not return an email.' });
      }

      // 1) If already linked by googleId, find it fast (any collection)
      let user =
        (await Member.findOne({ googleId })) ||
        (await Leader.findOne({ googleId })) ||
        (await GroupMember.findOne({ googleId }));

      // 2) Otherwise, link by email (member email vs leader groupLeaderEmail)
      if (!user) {
        user =
          (await Member.findOne({ email })) ||
          (await Leader.findOne({ groupLeaderEmail: email })) ||
          (await GroupMember.findOne({ email }));

        if (!user) {
          // No auto-create (schemas require too much)
          return done(null, false, { message: 'No Twennie account found for that Google email.' });
        }

        // Link googleId
        if (!user.googleId) user.googleId = googleId;

        // Optional: store avatar without overwriting your existing profileImage
        if (avatar && !user.avatar) user.avatar = avatar;

        // Optional: if a Member is missing name (shouldn't be), fill it
        if (displayName && !user.name && !user.groupLeaderName && !user.groupMemberName) {
          user.name = displayName;
        }

        await user.save();
      }

      return done(null, user);
    } catch (err) {
      console.error('❌ GoogleStrategy error:', err);
      return done(err, null);
    }
  }
));


// ✅ Google OAuth2 Strategy (Member, Leader, GroupMember)
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'https://www.twennie.com/auth/google/callback',
    proxy: true
  },
  async (_accessToken, _refreshToken, profile, done) => {
    try {
      const email = (profile.emails?.[0]?.value || '').toLowerCase();
      const googleId = profile.id;
      const avatar = profile.photos?.[0]?.value || null;

      if (!email) return done(null, false, { message: 'Google account did not return an email.' });

      // Find by googleId first
      let user =
        (await Member.findOne({ googleId })) ||
        (await Leader.findOne({ googleId })) ||
        (await GroupMember.findOne({ googleId }));

      // Otherwise link by email
      if (!user) {
        user =
          (await Member.findOne({ email })) ||
          (await Leader.findOne({ groupLeaderEmail: email })) ||
          (await GroupMember.findOne({ email }));

        if (!user) return done(null, false, { message: 'No Twennie account found for that Google email.' });

        user.googleId = user.googleId || googleId;
        if (avatar && !user.avatar) user.avatar = avatar;

        await user.save();
      }

      return done(null, user);
    } catch (err) {
      console.error('❌ GoogleStrategy error:', err);
      return done(err, null);
    }
  }
));




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






