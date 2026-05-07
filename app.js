// app.js (rewritten to restore header user locals & simplify auth flow)
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
const Handlebars = require('handlebars');

// Profiles (for userProfileImage lookup)
const MemberProfile = require('./models/profile_models/member_profile');
const LeaderProfile = require('./models/profile_models/leader_profile');
const GroupMemberProfile = require('./models/profile_models/groupmember_profile');

// User models (for inactive guard only)
const Member = require('./models/member_models/member');
const Leader = require('./models/member_models/leader');
const GroupMember = require('./models/member_models/group_member');

dotenv.config();

if (process.env.NODE_ENV === 'production') {
  const originalLog = console.log;

  console.log = (...args) => {
    const sanitized = args.map(arg => {
      if (arg && typeof arg === 'object') {
        const clone = { ...arg };

        delete clone.password;
        delete clone.secretEnc;
        delete clone.secretIv;
        delete clone.secretTag;
        delete clone.recoveryCodes;
        delete clone.resetPasswordToken;

        return clone;
      }
      return arg;
    });

    originalLog(...sanitized);
  };
}

const app = express();

/* ------------------------------------------------------------------
   RUNTIME / ENV
------------------------------------------------------------------- */
app.set('trust proxy', 1);
console.log('✅ NODE_ENV:', process.env.NODE_ENV);
console.log('✅ MONGO_URI present:', !!process.env.MONGO_URI);
console.log('✅ SESSION_SECRET present:', !!process.env.SESSION_SECRET);
console.log('✅ COOKIE_SECRET present:', !!process.env.COOKIE_SECRET);

app.locals.GA_ID = process.env.NODE_ENV === 'production' ? process.env.GA_MEASUREMENT_ID : null;

/* ------------------------------------------------------------------
   1) STRIPE WEBHOOKS — mount before body parsers (raw body inside router)
------------------------------------------------------------------- */
try {
  const webhookRoutes = require('./routes/webhooks');
  app.use('/webhooks', webhookRoutes);
  console.log('✅ Webhooks router mounted at /webhooks');
} catch (e) {
  console.error('⚠️ Failed to mount /webhooks:', e?.message || e);
}

/* ------------------------------------------------------------------
   2) HANDLEBARS
------------------------------------------------------------------- */
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
      add: function (a, b) {
    return Number(a) + Number(b);
  },
    inc: (value) => Number(value) + 1,
    replace: (string, find, rep) =>
      (typeof string === 'string' ? string.split(find).join(rep) : ''),
    formatContent: (c) => (c ? c.replace(/\n/g, '<br>') : ''),
    ifEquals: (a, b, opts) => (a === b ? opts.fn(this) : opts.inverse(this)),
    toLowerCase: (s) => (typeof s === 'string' ? s.toLowerCase() : ''),
    formatDate: (d) => (d ? moment(d).format('MMMM D, YYYY') : ''),
    eq: (v1, v2) => v1 === v2,
    ne: (v1, v2) => v1 !== v2,
    and: (v1, v2) => v1 && v2,
    or: (v1, v2) => v1 || v2,
    includes: (arr, val) => Array.isArray(arr) && arr.includes(val),
    ifIncludes: (arr, val, opts) =>
      (Array.isArray(arr) && arr.includes(val) ? opts.fn(this) : opts.inverse(this)),
    range: (start, end) => Array.from({ length: end - start }, (_, i) => start + i),
    concat: (a, b) => `${a}${b}`,
    lt: (a, b) => a < b,
    equal: (a, b) => a === b,
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
      const base = 'https://www.twennie.com/images/';
      const map = {
        article: '5mins.svg',
        video: '10mins.svg',
        interview: '10mins.svg',
        promptset: '20mins.svg',
        exercise: '30mins.svg',
        template: '30mins.svg',
      };
      return base + (map[unitType] || '5mins.svg');
    },
    capitalize: (s) =>
      (typeof s === 'string' ? s.charAt(0).toUpperCase() + s.slice(1) : ''),
    json: (ctx) => JSON.stringify(ctx, null, 2),
    increment: (v) => parseInt(v) + 1,
    timestamp: () => Date.now(),
    getYouTubeEmbedUrl: (url) => {
      if (!url) return '';
      if (url.includes('watch?v=')) {
        return `https://www.youtube.com/embed/${url.split('watch?v=')[1].split('&')[0]}`;
      }
      if (url.includes('youtu.be/')) {
        return `https://www.youtube.com/embed/${url.split('youtu.be/')[1].split('?')[0]}`;
      }
      return url;
    },
    split: (str, d) => (typeof str === 'string' ? str.split(d) : []),
    last: (arr) => (Array.isArray(arr) ? arr[arr.length - 1] : ''),
    decode: (s) => decodeURIComponent(s),

    // ✅ NEW helper
    nl2br: function (text) {
      if (!text) return '';
      const escaped = Handlebars.escapeExpression(text);
      const withBreaks = escaped.replace(/(?:\r\n|\r|\n)/g, '<br>');
      return new Handlebars.SafeString(withBreaks);
    },
  },
});


hbs.getPartials().then((partials) => console.log('🧩 Registered Partials:', Object.keys(partials)));
app.engine('hbs', hbs.engine);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

/* ------------------------------------------------------------------
   3) CORE MIDDLEWARE
------------------------------------------------------------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(cors());

// Static
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'public/images')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use('/icons', express.static(path.join(__dirname, 'public/icons')));

// Health
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// UI prefs → res.locals
app.use((req, res, next) => {
  try {
    res.locals.uiPrefs = req.cookies.tw_ui ? JSON.parse(req.cookies.tw_ui) : {};
  } catch {
    res.locals.uiPrefs = {};
  }
  next();
});

/* ------------------------------------------------------------------
   4) SESSION
------------------------------------------------------------------- */
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
    console.error('⚠️ MongoStore init failed, using MemoryStore:', e?.message || e);
  }
} else {
  console.warn('⚠️ MONGO_URI not set; using MemoryStore');
}

app.use(session(sessionOptions));

// Help caches/CDNs serve the right variant
app.use((req, res, next) => {
  res.set('Vary', 'Cookie');
  next();
});

// Consent → res.locals
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
   5) CSRF (with safe bypasses)
------------------------------------------------------------------- */
const csrfProtection = csrf();
app.use((req, res, next) => {
  const skipPaths = [
    '/member/group/verify-registration-code',
    '/badges/pick',
    '/webhooks/webhook', // verified by Stripe signature
  ];
  const csrfExemptDeletes = [/^\/promptsetregistration\/unregister\/[\w\d]+$/];
  const contentType = req.headers['content-type'] || '';

  if (contentType.startsWith('multipart/form-data')) return next();
  if (req.method === 'POST' && skipPaths.includes(req.path)) return next();
  if (req.method === 'DELETE' && csrfExemptDeletes.some((p) => p.test(req.path))) return next();

  return csrfProtection(req, res, next);
});

/* ------------------------------------------------------------------
   6) PASSPORT
------------------------------------------------------------------- */
try {
  require('./config/passport-config')(passport);
  console.log('✅ Passport config loaded');
} catch (e) {
  console.error('⚠️ Passport config failed to load:', e);
}
app.use(passport.initialize());
app.use(passport.session());

/* ------------------------------------------------------------------
   7) USER LOCALS (🔥 key fix for header)
   - Copy req.user → res.locals.user
   - Compute dashboardLink
   - Resolve profile image (best-effort) with safe default
------------------------------------------------------------------- */
/* ------------------------------------------------------------------
   7) USER LOCALS (MFA/Passport rehydration + promote into req.login)
   Fixes: req.user missing after MFA → req.isAuthenticated() false → redirects
------------------------------------------------------------------- */
app.use(async (req, res, next) => {
  try {
    // --- 1) Collect a candidate user id & type from various places ---
    let effectiveUser = req.user || null;
    let candidateId = (effectiveUser?._id || effectiveUser?.id || '').toString() || null;
    let candidateType = effectiveUser?.membershipType || null; // 'leader' | 'group_member' | 'member'

    // a) Your custom session user (often set pre/post MFA)
    if (!candidateId && req.session?.user) {
      const u = req.session.user;
      candidateId = (u._id || u.id || '').toString() || candidateId;
      candidateType = u.membershipType || candidateType;
    }

    // b) Passport session payload (some strategies store a string id, others an object)
    if (!candidateId && req.session?.passport?.user) {
      const u = req.session.passport.user;
      if (typeof u === 'string') {
        candidateId = u;
      } else if (u && typeof u === 'object') {
        candidateId = (u._id || u.id || '').toString() || candidateId;
        candidateType = u.membershipType || candidateType;
      }
    }

    // c) MFA staging buckets you may be using
    if (!candidateId && req.session?.mfa?.userId) {
      candidateId = String(req.session.mfa.userId);
      candidateType = req.session.mfa.membershipType || candidateType;
    }
    if (!candidateId && req.session?.mfaUserId) {
      candidateId = String(req.session.mfaUserId);
    }

    // --- 2) Hydrate a full user doc if req.user is absent/partial ---
    const asString = (v) => (v == null ? '' : String(v));
    async function hydrateById(id, hintedType) {
      if (!id) return null;

      // Fast path: if we know the type, fetch that collection first
      if (hintedType === 'leader') {
        const doc = await Leader.findById(id).lean();
        if (doc) return { ...doc, membershipType: 'leader' };
      } else if (hintedType === 'group_member') {
        const doc = await GroupMember.findById(id).lean();
        if (doc) return { ...doc, membershipType: 'group_member' };
      } else if (hintedType === 'member') {
        const doc = await Member.findById(id).lean();
        if (doc) return { ...doc, membershipType: 'member' };
      }

      // Try all three if type unknown or previous miss
      let doc = await Leader.findById(id).lean();
      if (doc) return { ...doc, membershipType: 'leader' };

      doc = await GroupMember.findById(id).lean();
      if (doc) return { ...doc, membershipType: 'group_member' };

      doc = await Member.findById(id).lean();
      if (doc) return { ...doc, membershipType: 'member' };

      return null;
    }

    let hydrated = effectiveUser;
    if (!hydrated || !asString(hydrated._id || hydrated.id)) {
      hydrated = await hydrateById(candidateId, candidateType);
      if (hydrated) {
        // Put on req so downstream policies work consistently
        req.user = hydrated;
        effectiveUser = hydrated;
      }
    }

    // --- 3) If Passport isn’t marked authenticated, promote the user into it ---
    if (hydrated && typeof req.isAuthenticated === 'function' && !req.isAuthenticated()) {
      await new Promise((resolve) => {
        req.login(hydrated, (err) => {
          if (err) {
            console.error('⚠️ req.login failed during hydration:', err?.message || err);
          }
          // Also mirror into your own session.user for compatibility
          req.session.user = {
            id: asString(hydrated._id || hydrated.id),
            membershipType: hydrated.membershipType,
            email: hydrated.email,
            accessLevel: hydrated.accessLevel,
            groupId: hydrated.groupId,
            organization: hydrated.organization,
            username: hydrated.username || hydrated.groupLeaderName || hydrated.name || 'user',
          };
          req.session.save(() => resolve());
        });
      });
    }

    // --- 4) Expose locals for header/templates ---
    const userForView = hydrated || null;
    res.locals.user = userForView;




    const typeNorm = asString(userForView?.membershipType).replace(/[_\-]/g, '').toLowerCase(); // leader | groupmember | member
    let dashboardLink = '/dashboard/member';
    if (typeNorm === 'leader') dashboardLink = '/dashboard/leader';
    else if (typeNorm === 'groupmember') dashboardLink = '/dashboard/groupmember';
    res.locals.dashboardLink = dashboardLink;

    // Resolve profile image
    let userProfileImage = null;
    const idForProfile = asString(userForView?._id || userForView?.id);
    if (idForProfile) {
      if (typeNorm === 'leader') {
        const p = await LeaderProfile.findOne({ leaderId: idForProfile }).select('profileImage').lean();
        userProfileImage = p?.profileImage || null;
      } else if (typeNorm === 'groupmember') {
        const p = await GroupMemberProfile.findOne({ groupMemberId: idForProfile }).select('profileImage').lean();
        userProfileImage = p?.profileImage || null;
      } else if (typeNorm === 'member') {
        const p = await MemberProfile.findOne({ memberId: idForProfile }).select('profileImage').lean();
        userProfileImage = p?.profileImage || null;
      }
    }
    if (!userProfileImage) userProfileImage = userForView?.profileImage || '/images/default-avatar.png';
    if (userProfileImage && !/^https?:\/\//i.test(userProfileImage)) {
      userProfileImage = userProfileImage.startsWith('/') ? userProfileImage : `/${userProfileImage}`;
    }
    res.locals.userProfileImage = userProfileImage;

    // Make sure caches choose the right variant
    res.set('Vary', 'Cookie');

    return next();
  } catch (e) {
    console.error('USER LOCALS hydrate error:', e?.message || e);
    res.locals.user = null;
    res.locals.dashboardLink = '/dashboard/member';
    res.locals.userProfileImage = '/images/default-avatar.png';
    return next();
  }
});




// ✅ Ensure /public/videos exists and MP4s get correct headers
app.use('/videos', express.static(path.join(__dirname, 'public', 'videos'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.mp4')) {
      res.type('video/mp4');            // sends Content-Type: video/mp4
      res.setHeader('Accept-Ranges','bytes'); // enable seeking, not strictly required but nice
    }
  }
}));

/* ------------------------------------------------------------------
   8) INACTIVE / CANCELED GUARD
------------------------------------------------------------------- */
app.use(async (req, res, next) => {
  try {
    if (req.user && typeof req.user.isActive === 'undefined') {
      let doc = null;
      if (req.user.membershipType === 'leader') {
        doc = await Leader.findById(req.user.id || req.user._id).select('isActive').lean();
      } else if (req.user.membershipType === 'group_member') {
        doc = await GroupMember.findById(req.user.id || req.user._id).select('isActive').lean();
      } else {
        doc = await Member.findById(req.user.id || req.user._id).select('isActive').lean();
      }
      req.user.isActive = doc?.isActive ?? true;
    }
  } catch (_) { /* ignore */ }
  next();
});

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
   9) MONGO CONNECT
------------------------------------------------------------------- */
if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch((err) => console.error('❌ MongoDB connection error:', err));
} else {
  console.warn('⚠️ MONGO_URI not set; skipping DB connect.');
}

/* ------------------------------------------------------------------
   10) ENSURE DIRECTORIES
------------------------------------------------------------------- */
['public/uploads/profiles', 'public/uploads/groups'].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});



/* ------------------------------------------------------------------
   11) ROUTES
------------------------------------------------------------------- */
app.use('/', require('./routes/promoroutes/promoroutes'));
app.use('/member', require('./routes/memberroutes'));
app.use('/member/group', require('./routes/groupmemberroutes'));


app.use('/dashboard/leader', require('./routes/leaderdashboardroutes'));
app.use('/dashboard/leader/org-admin', require('./routes/orgadminroutes'));

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
app.use('/', require('./routes/missionroutes'));
app.use('/search', require('./routes/searchroutes'));
app.use('/unitsuggestions', require('./routes/unitsuggestionroutes'));
app.use('/archive', require('./routes/archiveroutes'));




// Billing
try {
  app.use('/billing', require('./routes/billing'));
  console.log('✅ Billing routes mounted at /billing');
} catch (e) {
  console.error('⚠️ Failed to mount /billing routes:', e?.message || e);
}

/* ------------------------------------------------------------------
   12) ERRORS
------------------------------------------------------------------- */
app.use((err, req, res, next) => {
  if (err?.code === 'EBADCSRFTOKEN') {
    console.error('❌ CSRF token validation failed.');
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








