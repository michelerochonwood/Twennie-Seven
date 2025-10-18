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
const Member = require('./models/member_models/member');
const Leader = require('./models/member_models/leader');
const GroupMember = require('./models/member_models/group_member');

dotenv.config();

const app = express();

// ---- Runtime diagnostics / infra sanity ----
app.set('trust proxy', 1);
console.log('✅ NODE_ENV:', process.env.NODE_ENV);
console.log('✅ MONGO_URI present:', !!process.env.MONGO_URI);
console.log('✅ SESSION_SECRET present:', !!process.env.SESSION_SECRET);
console.log('✅ COOKIE_SECRET present:', !!process.env.COOKIE_SECRET);

// (Optional) expose GA ID to layouts if you choose to gate analytics by GA_ID
app.locals.GA_ID = process.env.NODE_ENV === 'production' ? process.env.GA_MEASUREMENT_ID : null;

/* ------------------------------------------------------------------
   1) STRIPE WEBHOOKS — MOUNT FIRST (RAW BODY INSIDE THE ROUTER)
   ------------------------------------------------------------------ */
try {
  const webhookRoutes = require('./routes/webhooks'); // defines POST /webhooks/stripe with express.raw
  app.use('/webhooks', webhookRoutes);
  console.log('✅ Webhooks router mounted at /webhooks');
} catch (e) {
  console.error('⚠️ Failed to mount /webhooks router:', e?.message || e);
}

// ---- Handlebars setup ----
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
    formatContent: (content) => (content ? content.replace(/\n/g, '<br>') : ''),
    ifEquals: function (a, b, options) {
      return a === b ? options.fn(this) : options.inverse(this);
    },
    toLowerCase: (str) => (typeof str === 'string' ? str.toLowerCase() : ''),
    formatDate: (date) => (date ? moment(date).format('MMMM D, YYYY') : ''),
    eq: (v1, v2) => v1 === v2,
    ne: (v1, v2) => v1 !== v2,
    and: (v1, v2) => v1 && v2,
    or: (v1, v2) => v1 || v2,
    includes: (array, value) => Array.isArray(array) && array.includes(value),
    ifIncludes: (array, value, options) =>
      Array.isArray(array) && array.includes(value) ? options.fn(this) : options.inverse(this),
    range: (start, end) => Array.from({ length: end - start }, (_, i) => start + i),
    concat: (str1, str2) => `${str1}${str2}`,
    lt: (a, b) => a < b,
    equal: (a, b) => a === b, // alias
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
    capitalize: (str) => (typeof str === 'string' ? str.charAt(0).toUpperCase() + str.slice(1) : ''),
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
    split: (str, delimiter) => (typeof str === 'string' ? str.split(delimiter) : []),
    last: (array) => (Array.isArray(array) ? array[array.length - 1] : ''),
    decode: (str) => decodeURIComponent(str),
  },
});

hbs.getPartials().then((partials) => {
  console.log('🧩 Registered Partials:', Object.keys(partials));
});

app.engine('hbs', hbs.engine);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

/* ------------------------------------------------------------------
   2) CORE MIDDLEWARE (after webhooks)
   ------------------------------------------------------------------ */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors());

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'public/images')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use('/icons', express.static(path.join(__dirname, 'public/icons')));

// Minimal health endpoint for platform checks
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// UI prefs
app.use((req, res, next) => {
  try {
    res.locals.uiPrefs = req.cookies.tw_ui ? JSON.parse(req.cookies.tw_ui) : {};
  } catch {
    res.locals.uiPrefs = {};
  }
  next();
});

/* ------------------------------------------------------------------
   3) SESSION
   ------------------------------------------------------------------ */
const sessionOptions = {
  secret: process.env.SESSION_SECRET || 'defaultsecret',
  resave: true,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
  },
};

if (process.env.MONGO_URI) {
  try {
    sessionOptions.store = MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions',
      ttl: 7 * 24 * 60 * 60,
      autoRemove: 'interval',
      autoRemoveInterval: 10,
    });
    console.log('✅ Session store: Mongo');
  } catch (e) {
    console.error('⚠️ Failed to init MongoStore, falling back to MemoryStore:', e);
  }
} else {
  console.warn('⚠️ MONGO_URI not set; using MemoryStore for sessions.');
}

app.use(session(sessionOptions));

// Optional: help CDNs serve the right variant
app.use((req, res, next) => {
  res.set('Vary', 'Cookie');
  next();
});

// Consent locals (must come before views/routes)
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

/* ------------------------------------------------------------------
   4) CSRF (with safe bypasses)
   ------------------------------------------------------------------ */
const csrfProtection = csrf();
app.use((req, res, next) => {
  const skipPaths = [
    '/member/group/verify-registration-code',
    '/badges/pick',
    '/webhooks/stripe', // ⬅️ Stripe webhooks bypass CSRF (verified by signature instead)
  ];
  const csrfExemptDeletes = [/^\/promptsetregistration\/unregister\/[\w\d]+$/];
  const contentType = req.headers['content-type'] || '';

  if (contentType.startsWith('multipart/form-data')) return next();
  if (req.method === 'POST' && skipPaths.includes(req.path)) return next();
  if (req.method === 'DELETE' && csrfExemptDeletes.some((p) => p.test(req.path))) return next();

  return csrfProtection(req, res, next);
});

/* ------------------------------------------------------------------
   5) LOGGING + PASSPORT
   ------------------------------------------------------------------ */
app.use((req, _res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.url} - User: ${req.session?.user?.username || 'Guest'}`
  );
  next();
});

try {
  require('./config/passport-config')(passport);
  console.log('✅ Passport config loaded');
} catch (e) {
  console.error('⚠️ Passport config failed to load:', e);
}
app.use(passport.initialize());
app.use(passport.session());

// Normalize req.user if only session user exists - we deleted this - ask ChatGPT why


// AFTER: app.use(passport.session());
// BEFORE: the inactive-logout guard
app.use(async (req, res, next) => {
  try {
    if (req.user && typeof req.user.isActive === 'undefined') {
      let doc = null;
      if (req.user.membershipType === 'leader') {
        doc = await Leader.findById(req.user.id).select('isActive').lean();
      } else if (req.user.membershipType === 'group_member') {
        doc = await GroupMember.findById(req.user.id).select('isActive').lean();
      } else {
        doc = await Member.findById(req.user.id).select('isActive').lean();
      }
      req.user.isActive = doc?.isActive ?? true;
    }
  } catch (e) { /* non-blocking */ }
  next();
});

// Inactive logout guard
app.use((req, res, next) => {
  if (req.user && req.user.isActive === false) {
    req.logout?.(() => {});
    req.session.destroy(() => {
      return res.status(403).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Account Inactive',
        errorMessage: 'Your account is inactive. Please contact support to reinstate your membership.'
      });
    });
    return;
  }
  next();
});

/* ------------------------------------------------------------------
   6) MONGO CONNECT
   ------------------------------------------------------------------ */
if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch((err) => {
      console.error('❌ MongoDB connection error:', err);
    });
} else {
  console.warn('⚠️ MONGO_URI not set; skipping DB connect.');
}

/* ------------------------------------------------------------------
   7) ENSURE DIRECTORIES
   ------------------------------------------------------------------ */
['public/uploads/profiles', 'public/uploads/groups'].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

/* ------------------------------------------------------------------
   8) ROUTES
   ------------------------------------------------------------------ */
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
app.use('/badges', require('./routes/badgesroutes'));
app.use('/dashboard', require('./routes/preferenceroutes'));
app.use('/ui', require('./routes/uiroutes'));

// ⬇️ New: Billing routes
try {
  app.use('/billing', require('./routes/billing'));
  console.log('✅ Billing routes mounted at /billing');
} catch (e) {
  console.error('⚠️ Failed to mount /billing routes:', e?.message || e);
}

/* ------------------------------------------------------------------
   9) ERRORS
   ------------------------------------------------------------------ */
app.use((err, req, res, next) => {
  if (err?.code === 'EBADCSRFTOKEN') {
    console.error('❌ CSRF token validation failed.');
    console.error('Request body at failure:', JSON.stringify(req.body, null, 2));
    console.error('Session at failure:', JSON.stringify(req.session, null, 2));
    return res.status(403).render('member_form_views/error', {
      layout: 'memberformlayout',
      title: 'CSRF Error',
      errorMessage: 'Form submission failed for security reasons. Please refresh the page and try again.',
    });
  }
  return next(err);
});

app.use((req, res) => {
  console.warn(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).render('member_form_views/error', {
    layout: 'memberformlayout',
    title: 'Page Not Found',
    errorMessage: 'The page you are looking for does not exist.',
  });
});

app.use((err, req, res, _next) => {
  console.error('Server Error:', err);
  const layout = req.originalUrl.startsWith('/member') ? 'memberformlayout' : 'mainlayout';
  res.status(500).render('member_form_views/error', {
    layout,
    title: 'Server Error',
    errorMessage: process.env.NODE_ENV === 'development' ? err.message : 'An internal server error occurred.',
  });
});

module.exports = app;








