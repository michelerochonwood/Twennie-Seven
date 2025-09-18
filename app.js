// app.js
const express = require('express');
const path = require('path');
const { create } = require('express-handlebars');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const moment = require('moment');
const passport = require('passport');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const csrf = require('csurf');

// Profiles used in global session middleware
const MemberProfile = require('./models/profile_models/member_profile');
const LeaderProfile = require('./models/profile_models/leader_profile');
const GroupMemberProfile = require('./models/profile_models/groupmember_profile');

// User models for membership detection
const Member = require("./models/member_models/member");
const Leader = require("./models/member_models/leader");
const GroupMember = require("./models/member_models/group_member");

dotenv.config();

const app = express();

// ✅ Trust proxy for secure cookies on Railway / reverse proxies
app.set('trust proxy', 1);

console.log("✅ MONGO_URI in use:", process.env.MONGO_URI);

// (Optional) expose GA ID to layouts if you choose to gate analytics by GA_ID
app.locals.GA_ID = process.env.NODE_ENV === 'production' ? process.env.GA_MEASUREMENT_ID : null;

// ✅ Handlebars setup
const hbs = create({
  extname: '.hbs',
  layoutsDir: path.join(__dirname, 'views/layouts'),
  partialsDir: path.join(__dirname, 'views/partials'),
  defaultLayout: 'mainlayout',
  runtimeOptions: {
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true,
  },
  helpers: {
    replace: (string, find, replace) =>
      typeof string === 'string' ? string.split(find).join(replace) : '',

    formatContent: (content) =>
      content ? content.replace(/\n/g, '<br>') : '',

    ifEquals: function (a, b, options) {
      return a === b ? options.fn(this) : options.inverse(this);
    },

    toLowerCase: (str) =>
      typeof str === 'string' ? str.toLowerCase() : '',

    formatDate: (date) =>
      date ? moment(date).format('MMMM D, YYYY') : '',

    eq: (v1, v2) => v1 === v2,
    ne: (v1, v2) => v1 !== v2,
    and: (v1, v2) => v1 && v2,
    or: (v1, v2) => v1 || v2,

    includes: (array, value) =>
      Array.isArray(array) && array.includes(value),

    ifIncludes: (array, value, options) =>
      Array.isArray(array) && array.includes(value)
        ? options.fn(this)
        : options.inverse(this),

    range: (start, end) =>
      Array.from({ length: end - start }, (_, i) => start + i),

    concat: (str1, str2) => `${str1}${str2}`,
    lt: (a, b) => a < b,
    equal: (a, b) => a === b, // redundant alias

    getUnitTypeIcon: (unitType) => {
      const icons = {
        article: '/icons/article.svg',
        video: '/icons/video.svg',
        interview: '/icons/interview.svg',
        promptset: '/icons/promptset.svg',
        exercise: '/icons/exercise.svg',
        template: '/icons/template.svg',
      };
      return icons[unitType] || '/icons/default.svg';
    },

    getDurationImage: (unitType) => {
      const baseURL = 'https://www.twennie.com/images/';
      const map = {
        article: '5mins.svg',
        video: '10mins.svg',
        interview: '10mins.svg',
        promptset: '20mins.svg',
        exercise: '30mins.svg',
        template: '30mins.svg',
      };
      if (!map[unitType]) {
        console.warn(`⚠️ Unrecognized unitType for duration image: ${unitType}`);
      }
      return baseURL + (map[unitType] || '5mins.svg');
    },

    capitalize: (str) =>
      typeof str === 'string' ? str.charAt(0).toUpperCase() + str.slice(1) : '',

    json: (context) => JSON.stringify(context, null, 2),
    increment: (value) => parseInt(value) + 1,
    timestamp: () => Date.now(),

    getYouTubeEmbedUrl: (url) => {
      if (!url) return '';
      if (url.includes('watch?v=')) {
        const videoId = url.split('watch?v=')[1].split('&')[0];
        return `https://www.youtube.com/embed/${videoId}`;
      }
      if (url.includes('youtu.be/')) {
        const videoId = url.split('youtu.be/')[1].split('?')[0];
        return `https://www.youtube.com/embed/${videoId}`;
      }
      return url;
    },

    // NEW: Split a string by delimiter
    split: (str, delimiter) =>
      typeof str === 'string' ? str.split(delimiter) : [],

    // NEW: Get last item in array
    last: (array) =>
      Array.isArray(array) ? array[array.length - 1] : '',

    decode: (str) => decodeURIComponent(str),
  }
});

hbs.getPartials().then((partials) => {
  console.log('Registered Partials:', Object.keys(partials));
});

app.engine('hbs', hbs.engine);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// ✅ Parsers & core middleware (order matters)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors());

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'public/images')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.use((req, res, next) => {
  try {
    res.locals.uiPrefs = req.cookies.tw_ui ? JSON.parse(req.cookies.tw_ui) : {};
  } catch {
    res.locals.uiPrefs = {};
  }
  next();
});

// ✅ Session (before CSRF, passport, routes)
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions',
      ttl: 7 * 24 * 60 * 60,
      autoRemove: 'interval',
      autoRemoveInterval: 10
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax'
    }
  })
);

// Optional: help CDNs serve the right variant
app.use((req, res, next) => { res.set('Vary', 'Cookie'); next(); });

// ✅ Consent locals (must come before views/routes)
app.use((req, res, next) => {
  const defaults = { version: 1, necessary: true, functional: false, analytics: false, marketing: false };
  try {
    const fromCookie = req.cookies.twennieConsent ? JSON.parse(req.cookies.twennieConsent) : {};
    res.locals.consent = { ...defaults, ...fromCookie };
  } catch {
    res.locals.consent = defaults;
  }
  next();
});

// ✅ CSRF setup (after session)
// ✅ CSRF setup (after session)
const csrfProtection = csrf();

app.use((req, res, next) => {
  const skipPaths = [
    '/member/group/verify-registration-code',
    '/badges/pick', // ← allow this POST without CSRF token
  ];

  const csrfExemptDeletes = [
    /^\/promptsetregistration\/unregister\/[\w\d]+$/
  ];

  const contentType = req.headers['content-type'] || '';

  // Rules: allow multipart (uploads), selected POSTs, and specific DELETEs to bypass CSRF
  if (contentType.startsWith('multipart/form-data')) return next();
  if (req.method === 'POST' && skipPaths.includes(req.path)) return next();
  if (req.method === 'DELETE' && csrfExemptDeletes.some(pattern => pattern.test(req.path))) return next();

  return csrfProtection(req, res, next);
});


// ✅ Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - User: ${req.session?.user?.username || 'Guest'}`);
  next();
});

// ✅ Passport
require('./config/passport-config')(passport);
app.use(passport.initialize());
app.use(passport.session());

// AFTER: app.use(passport.initialize()); app.use(passport.session());
app.use((req, res, next) => {
  // If Passport didn't set req.user but we have a session login (MFA path), normalize it.
  if (!req.user && req.session?.user?.id) {
    const s = req.session.user;
    // Minimal shape most controllers expect
    req.user = {
      id: s.id,                // string OK for Mongoose findById
      _id: s.id,               // strings have toString(), so calls like _id.toString() won't throw
      username: s.username,
      membershipType: s.membershipType,
      // helpful default: leaders treat their own id as groupId for "team_only" checks
      groupId: s.membershipType === 'leader' ? s.id : undefined,
      // organization is optional; if you need org-only visibility, we can enrich this later
    };
  }

  // Make req.isAuthenticated() reflect session-only logins too
  if (typeof req.isAuthenticated === 'function') {
    const orig = req.isAuthenticated.bind(req);
    req.isAuthenticated = function () {
      return orig() || !!req.session?.user;
    };
  }

  next();
});


// Stripe webhook (assumes its route sets its own body parser if needed)
app.use('/stripe', require('./routes/stripe/stripewebhook'));

// ✅ Global user session middleware (dashboard link + profile avatar)
app.use(async (req, res, next) => {
  if (req.session?.user?.id) {
    try {
      let membershipType = req.session.user.membershipType;
      const [member, leader, groupMember] = await Promise.all([
        Member.findById(req.session.user.id),
        Leader.findById(req.session.user.id),
        GroupMember.findById(req.session.user.id)
      ]);

      if (member) membershipType = "member";
      else if (leader) membershipType = "leader";
      else if (groupMember) membershipType = "group_member";

req.session.user.membershipType = membershipType;

// Canonical paths per role (no underscore in URL)
const roleToPath = {
  leader: '/dashboard/leader',
  group_member: '/dashboard/groupmember',
  member: '/dashboard/member'
};

res.locals.dashboardLink = roleToPath[membershipType] || '/dashboard';
console.log(`✅ dashboardLink set: ${res.locals.dashboardLink}`);

    } catch (err) {
      console.error("❌ Error retrieving membershipType:", err);
      res.locals.dashboardLink = "/dashboard";
    }
  } else {
    res.locals.dashboardLink = "/dashboard";
  }

const sessionUser  = req.session?.user || null;
const passportUser = req.user || null;

res.locals.user = passportUser || sessionUser;

res.locals.isAuthenticated =
  (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) || !!sessionUser;


  res.locals.userProfileImage = '/images/default-avatar.png'; // fallback

  try {
    if (req.session?.user?.id) {
      const { id, membershipType } = req.session.user;

      if (membershipType === 'member') {
        const profile = await MemberProfile.findOne({ memberId: id }).lean();
        if (profile?.profileImage) res.locals.userProfileImage = profile.profileImage;
      } else if (membershipType === 'leader') {
        const profile = await LeaderProfile.findOne({ leaderId: id }).lean();
        if (profile?.profileImage) res.locals.userProfileImage = profile.profileImage;
      } else if (membershipType === 'group_member') {
        const profile = await GroupMemberProfile.findOne({ groupMemberId: id }).lean();
        if (profile?.profileImage) res.locals.userProfileImage = profile.profileImage;
      }
    }
  } catch (err) {
    console.error('❌ Error loading profile image:', err);
  }

  next();
});

// ✅ MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ✅ Ensure directories exist
['public/uploads/profiles', 'public/uploads/groups'].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ✅ Routes
app.use('/', require('./routes/promoroutes/promoroutes'));
app.use('/member', require('./routes/memberroutes'));
app.use('/member/group', require('./routes/groupmemberroutes'));
app.use('/dashboard/leader', require('./routes/leaderdashboardroutes'));
app.use('/dashboard/groupmember', require('./routes/groupmemberdashboardroutes'));
app.use('/dashboard/group_member', require('./routes/groupmemberdashboardroutes'));
app.use('/dashboard/member', require('./routes/memberdashboardroutes'));
app.use('/leader', require('./routes/leaderroutes'));
app.use('/auth', require('./routes/loginroutes'));
app.use('/profile', require('./routes/profileroutes'));
app.use('/topics', require('./routes/topicroutes'));
app.use('/unitform', require('./routes/unitformroutes'));
app.use('/unitviews', require('./routes/unitviewroutes'));
app.use('/bytopic', require('./routes/bytopicroutes'));
app.use('/tags', require('./routes/tagroutes'));
app.use('/promptsetregistration', require('./routes/promptsetregistrationroutes'));
app.use('/promptsetassign', require('./routes/promptsetassignroutes'));
app.use('/promptsetnotes', require('./routes/promptsetnotesroutes'));
app.use('/promptsetcomplete', require('./routes/promptsetcompleteroutes'));
app.use('/membertopics', require('./routes/membertopicroutes'));
app.use('/mfa', require('./routes/mfaroutes'));
app.use('/privacy', require('./routes/privacyroutes'));
app.use('/notes', require('./routes/notesroutes'));
app.use('/reports', require('./routes/reportingroutes'));
app.use('/latest', require('./routes/latestroutes'));
app.use('/promptsetstart', require('./routes/promptsetstartroutes'));
app.use('/change_membership', require('./routes/changemembershiproutes'));
app.use('/badges', require('./routes/badgesroutes')); // keep badges route
app.use('/dashboard', require('./routes/preferenceroutes'));
app.use('/ui', require('./routes/uiroutes'));


// ✅ CSRF Error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.error('❌ CSRF token validation failed.');
    console.error('Request body at failure:', JSON.stringify(req.body, null, 2));
    console.error('Session at failure:', JSON.stringify(req.session, null, 2));
    return res.status(403).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'CSRF Error',
      errorMessage: 'Form submission failed for security reasons. Please refresh the page and try again.',
    });
  }
  next(err);
});

// ✅ 404 handler
app.use((req, res) => {
  console.warn(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).render('member_form_views/error', {
    layout: 'memberformlayout',
    title: 'Page Not Found',
    errorMessage: 'The page you are looking for does not exist.',
  });
});

// ✅ General error handler
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  const layout = req.originalUrl.startsWith('/member') ? 'memberformlayout' : 'mainlayout';
  res.status(500).render('member_form_views/error', {
    layout,
    title: 'Server Error',
    errorMessage: process.env.NODE_ENV === 'development' ? err.message : 'An internal server error occurred.',
  });
});

module.exports = app;






