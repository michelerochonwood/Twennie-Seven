const express = require('express');
const router = express.Router();
const twenniemapController = require('../../controllers/twenniemapController');
const createLearningController = require('../../controllers/createlearningController');
const Member = require('../../models/member_models/member');
const Leader = require('../../models/member_models/leader');
const GroupMember = require('../../models/member_models/group_member');

// Define routes
router.get('/', (req, res) => {
    res.render('promo_views/main_home_page', {
        layout: 'mainlayout'
    });
});

router.get('/avail_memberships', (req, res) => {
    res.render('promo_views/avail_memberships', {
        layout: 'mainlayout'
    });
});

router.get('/topics', (req, res) => {
    res.render('promo_views/topics', {
        layout: 'mainlayout'
    });
});

router.get('/contributor_units', (req, res) => {
    res.render('promo_views/contributor_units', {
        layout: 'mainlayout'
    });
});

router.get('/member_access', (req, res) => {
    res.render('promo_views/member_access', {
        layout: 'mainlayout'
    });
});




router.get('/what_is_twennie', (req, res) => {
    res.render('promo_views/whatistwennie_view', {
        layout: 'mainlayout'
    });
});

router.get('/about_twennie', (req, res) => {
    res.render('promo_views/about_twennie', {
        layout: 'mainlayout'
    });
});

router.get('/contribute', (req, res) => {
    res.render('promo_views/contribute', {
        layout: 'mainlayout'
    });
});

router.get('/microstudies', (req, res) => {
    res.render('promo_views/microstudies', {
        layout: 'mainlayout'
    });
});

router.get('/microcourses', (req, res) => {
    res.render('promo_views/microcourses', {
        layout: 'mainlayout'
    });
});

router.get('/peercoaching', (req, res) => {
    res.render('promo_views/peercoaching', {
        layout: 'mainlayout'
    });
});

router.get('/privacypolicy', (req, res) => {
    res.render('promo_views/privacypolicy', {
        layout: 'mainlayout'
    });
});

// --- Terms & Conditions (GET) ---
router.get('/termsconditions', (req, res) => {
  const u = res.locals.user || req.user || null;
  const next = req.query.next || '/dashboard';

  try {
    return res.render('promo_views/termsconditions', {
      layout: 'mainlayout',
      user: u,
      next,
      csrfToken: req.csrfToken ? req.csrfToken() : null,
    });
  } catch (err) {
    console.error('Error rendering termsconditions:', err);
    return res.status(500).render('promo_views/main_home_page', {
      layout: 'mainlayout',
    });
  }
});


// --- Terms & Conditions (POST accept) ---
router.post('/termsconditions/accept', async (req, res) => {
  const next = req.body.next || req.query.next || '/dashboard';

  try {
    // Must be logged in to accept
    if (!req.user || !req.user._id) {
      return res.status(401).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: null,
        next,
        csrfToken: req.csrfToken ? req.csrfToken() : null,
        errorMessage: 'Please log in to accept the Terms & Conditions.',
      });
    }

    // Server-side validation (don’t rely only on HTML required attr)
    if (!req.body.acceptTerms) {
      return res.status(400).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: req.user,
        next,
        csrfToken: req.csrfToken ? req.csrfToken() : null,
        errorMessage: 'Please check the box to accept the Terms & Conditions.',
      });
    }

    // Persist acceptance
// Persist acceptance (explicit model update — works even if req.user isn't a Mongoose doc)
const updates = {
  termsAccepted: true,
  termsAcceptedAt: new Date(),
  termsVersion: 'v1',
};

const userId = req.user._id;
const type = req.user.membershipType;

if (type === 'leader') {
  await Leader.findByIdAndUpdate(userId, updates);
} else if (type === 'group_member') {
  await GroupMember.findByIdAndUpdate(userId, updates);
} else {
  await Member.findByIdAndUpdate(userId, updates);
}

return res.redirect(next);

  } catch (err) {
    const isCsrfError = err && err.code === 'EBADCSRFTOKEN';
    console.error('Error accepting terms:', err);

    if (isCsrfError) {
      return res.status(403).render('promo_views/termsconditions', {
        layout: 'mainlayout',
        user: res.locals.user || req.user || null,
        next,
        csrfToken: req.csrfToken ? req.csrfToken() : null,
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('promo_views/termsconditions', {
      layout: 'mainlayout',
      user: res.locals.user || req.user || null,
      next,
      csrfToken: req.csrfToken ? req.csrfToken() : null,
      errorMessage: 'Could not save your terms acceptance. Please try again.',
    });
  }
});


router.get('/facilitation', (req, res) => {
    res.render('promo_views/facilitation', {
        layout: 'mainlayout'
    });
});

router.get('/promptset_promo', (req, res) => {
    res.render('promo_views/promptset_promo', {
        layout: 'mainlayout'
    });
});

router.get('/sample_article', (req, res) => {
    res.render('promo_views/sample_article', {
        layout: 'unitviewlayout'
    });
});

router.get('/sample_video', (req, res) => {
    res.render('promo_views/sample_video', {
        layout: 'unitviewlayout'
    });
});

router.get('/sample_promptset', (req, res) => {
    res.render('promo_views/sample_promptset', {
        layout: 'unitviewlayout'
    });
});

router.get('/custom_services', (req, res) => {
    res.render('promo_views/custom_services', {
        layout: 'mainlayout'
    });
});

router.get('/group_memberships', (req, res) => {
    res.render('promo_views/group_memberships', {
        layout: 'mainlayout'
    });
});

router.get('/sample_exercise', (req, res) => {
    res.render('promo_views/sample_exercise', {
        layout: 'mainlayout'
    });
});

router.get('/sample_template', (req, res) => {
    res.render('promo_views/sample_template', {
        layout: 'mainlayout'
    });
});

router.get('/sample_nugget', (req, res) => {
    res.render('promo_views/sample_nugget', {
        layout: 'mainlayout'
    });
});

router.get('/sample_mission', (req, res) => {
  res.render('promo_views/sample_mission', { layout: 'mainlayout' });
});

router.get('/sample_upcoming', (req, res) => {
  res.render('promo_views/sample_upcoming', { layout: 'mainlayout' });
});

router.get('/teach_me', twenniemapController.getTeachMe);

router.get('/training_bingo', (req, res) => {
    res.render('promo_views/training_bingo', {
        layout: 'mainlayout'
    });
});

router.get('/enterprise_members', (req, res) => {
    res.render('promo_views/enterprise_members', {
        layout: 'mainlayout'
    });
});

// ✅ Create Learning (orientation / instructional)
router.get('/create_learning', (req, res) => {
  // Use the already-hydrated locals from app.js
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


// Export the router
module.exports = router;
