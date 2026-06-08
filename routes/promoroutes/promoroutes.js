const express = require('express');
const router = express.Router();
const latestController = require('../../controllers/latestController');

const twenniemapController = require('../../controllers/twenniemapController');
const createLearningController = require('../../controllers/createlearningController');

const Member = require('../../models/member_models/member');
const Leader = require('../../models/member_models/leader');
const GroupMember = require('../../models/member_models/group_member');

// ✅ CSRF (needed for terms acceptance)
const csrf = require('csurf');
const csrfProtection = csrf();

// ------------------------------------------------------------
// Helpers (Terms flow)
// ------------------------------------------------------------
// NOTE: your actual dashboard route is /dashboard/groupmember (no dash).
// Schema name "group_member" does NOT determine the URL path.
function dashboardHomeForUser(user) {
  const type = user?.membershipType || user?.accessLevel;
  if (type === 'leader') return '/dashboard/leader#contribute';
  if (type === 'group_member') return '/dashboard/groupmember#contribute'; // ✅ real route
  return '/dashboard/member#contribute';
}

function sanitizeNext(next, user) {
  const fallback = dashboardHomeForUser(user);

  // must be a local path
  if (typeof next !== 'string') return fallback;
  if (!next.startsWith('/')) return fallback;
  if (next.startsWith('//')) return fallback;
  if (next.includes('://')) return fallback;

  // role-based allowlist
  const type = user?.membershipType || user?.accessLevel;

  if (type === 'leader') {
    if (next.startsWith('/dashboard/leader')) return next;
    if (next.startsWith('/unitform/')) return next;
    if (next.startsWith('/termsconditions')) return next;
    return fallback;
  }

  if (type === 'group_member') {
    // group members can NOT go to leader dashboard
    if (next.startsWith('/dashboard/groupmember')) return next;
    if (next.startsWith('/unitform/')) return next;
    if (next.startsWith('/termsconditions')) return next;
    return fallback;
  }

  // individual members
  if (next.startsWith('/dashboard/member')) return next;
  if (next.startsWith('/unitform/')) return next;
  if (next.startsWith('/termsconditions')) return next;

  return fallback;
}

// ------------------------------------------------------------
// Promo / public routes
// ------------------------------------------------------------
router.get('/', latestController.getHomePage);

router.get('/avail_memberships', (req, res) => {
  res.render('promo_views/avail_memberships', { layout: 'mainlayout' });
});

router.get('/topics', (req, res) => {

  const topicSignals = [
    "Conducting Market Research",
    "Proposal Strategy",
    "Leadership in Technical Consulting",
    "Managing Scope So It Doesnt Manage You"
  ];

  res.render('promo_views/topics', {
    layout: 'mainlayout',
    topicSignals
  });

});

router.get('/contributor_units', (req, res) => {
  res.render('promo_views/contributor_units', { layout: 'mainlayout' });
});

router.get('/member_access', (req, res) => {
  res.render('promo_views/member_access', { layout: 'mainlayout' });
});

router.get('/what_is_twennie', (req, res) => {
  res.render('promo_views/whatistwennie_view', { layout: 'mainlayout' });
});

router.get('/about_twennie', (req, res) => {
  res.render('promo_views/about_twennie', { layout: 'mainlayout' });
});

router.get('/contribute', (req, res) => {
  res.render('promo_views/contribute', { layout: 'mainlayout' });
});

router.get('/microstudies', (req, res) => {
  res.render('promo_views/microstudies', { layout: 'mainlayout' });
});

router.get('/microcourses', (req, res) => {
  res.render('promo_views/microcourses', { layout: 'mainlayout' });
});

router.get('/peercoaching', (req, res) => {
  res.render('promo_views/peercoaching', { layout: 'mainlayout' });
});

router.get('/privacypolicy', (req, res) => {
  res.render('promo_views/privacypolicy', { layout: 'mainlayout' });
});

router.get('/featureweek', (req, res) => {
  res.render('promo_views/feature_week', { layout: 'mainlayout' });
});

// ------------------------------------------------------------
// Terms & Conditions
// ------------------------------------------------------------

// GET: Terms page (must be csurf-protected so the form can generate a token)
router.get('/termsconditions', csrfProtection, (req, res) => {
  const u = res.locals.user || req.user || null;
  const next = sanitizeNext(req.query.next, u);

  try {
    return res.render('promo_views/termsconditions', {
      layout: 'mainlayout',
      user: u,
      next,
      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('Error rendering termsconditions:', err);
    return res.status(500).render('promo_views/main_home_page', { layout: 'mainlayout' });
  }
});

// POST: Accept Terms (csurf-protected + role-safe redirect)
router.post('/termsconditions/accept', csrfProtection, async (req, res) => {
  const u = res.locals.user || req.user || null;

  const rawNext = req.body.next || req.query.next;
  const next = sanitizeNext(rawNext, u);

  try {
    const userId = req.user?._id || req.user?.id;
    if (!req.user || !userId) {
      return res.status(401).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: null,
        next,
        csrfToken: req.csrfToken(),
        errorMessage: 'Please log in to accept the Terms &amp; Conditions.',
      });
    }

    if (!req.body.acceptTerms) {
      return res.status(400).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: u,
        next,
        csrfToken: req.csrfToken(),
        errorMessage: 'Please check the box to accept the Terms &amp; Conditions.',
      });
    }

    const updates = {
      termsAccepted: true,
      termsAcceptedAt: new Date(),
      termsVersion: 'v1',
    };

    const type = req.user.membershipType;

    if (type === 'leader') {
      await Leader.findByIdAndUpdate(userId, updates);
    } else if (type === 'group_member') {
      await GroupMember.findByIdAndUpdate(userId, updates);
    } else {
      await Member.findByIdAndUpdate(userId, updates);
    }

    // keep session user in sync
    req.user.termsAccepted = true;
    req.user.termsAcceptedAt = updates.termsAcceptedAt;
    req.user.termsVersion = updates.termsVersion;

    return res.redirect(next);

  } catch (err) {
    const isCsrfError = err && err.code === 'EBADCSRFTOKEN';
    console.error('Error accepting terms:', err);

    if (isCsrfError) {
      return res.status(403).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: u,
        next,
        csrfToken: req.csrfToken(),
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('promo_views/termsconditions', {
      layout: 'mainlayout',
      user: u,
      next,
      csrfToken: req.csrfToken(),
      errorMessage: 'Could not save your terms acceptance. Please try again.',
    });
  }
});

// ------------------------------------------------------------
// More promo routes
// ------------------------------------------------------------
router.get('/facilitation', (req, res) => {
  res.render('promo_views/facilitation', { layout: 'mainlayout' });
});

router.get('/promptset_promo', (req, res) => {
  res.render('promo_views/promptset_promo', { layout: 'mainlayout' });
});

router.get('/sample_article', (req, res) => {
  res.render('promo_views/sample_article', { layout: 'unitviewlayout' });
});

router.get('/sample_video', (req, res) => {
  res.render('promo_views/sample_video', { layout: 'unitviewlayout' });
});

router.get('/sample_promptset', (req, res) => {
  res.render('promo_views/sample_promptset', { layout: 'unitviewlayout' });
});

router.get('/custom_services', (req, res) => {
  res.render('promo_views/custom_services', { layout: 'mainlayout' });
});

router.get('/group_memberships', (req, res) => {
  res.render('promo_views/group_memberships', { layout: 'mainlayout' });
});

router.get('/themine_upgrade', (req, res) => {
  res.render('promo_views/group_upgrade_required_themine', { layout: 'mainlayout' });
});

router.get('/missioncontrol_upgrade', (req, res) => {
  res.render('promo_views/group_upgrade_required_mission', { layout: 'mainlayout' });
});

router.get('/sample_exercise', (req, res) => {
  res.render('promo_views/sample_exercise', { layout: 'mainlayout' });
});

router.get('/sample_template', (req, res) => {
  res.render('promo_views/sample_template', { layout: 'mainlayout' });
});

router.get('/sample_interview', (req, res) => {
  res.render('promo_views/sample_interview', { layout: 'mainlayout' });
});

router.get('/sample_nugget', (req, res) => {
  res.render('promo_views/sample_nugget', { layout: 'mainlayout' });
});

router.get('/sample_mission', (req, res) => {
  res.render('promo_views/sample_mission', { layout: 'mainlayout' });
});

router.get('/sample_upcoming', (req, res) => {
  res.render('promo_views/sample_upcoming', { layout: 'mainlayout' });
});

router.get('/security_privacy', (req, res) => {
  res.render('promo_views/security_privacy', {
    layout: 'mainlayout'
  });
});

router.get('/teach_me', twenniemapController.getTeachMe);

router.get('/training_bingo', (req, res) => {
  res.render('promo_views/training_bingo', { layout: 'mainlayout' });
});

router.get('/enterprise_members', (req, res) => {
  res.render('promo_views/enterprise_members', { layout: 'mainlayout' });
});

// ✅ Create Learning (orientation / instructional)
router.get('/create_learning', (req, res) => {
  const u = res.locals.user || req.user || null;

  const canContribute = !!u && (
    // leader
    !!u.groupLeaderEmail || u.membershipType === 'leader' ||
    // group member
    u.membershipType === 'group_member' ||
    // paid / contributor individual
    (
      (u.membershipType === 'member' || !!u.email) &&
      (u.accessLevel === 'paid_individual' || u.accessLevel === 'contributor_individual')
    )
  );

  return res.render('promo_views/creating_content', {
    layout: 'mainlayout',
    canContribute
  });
});

module.exports = router;

