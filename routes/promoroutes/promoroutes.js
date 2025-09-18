const express = require('express');
const router = express.Router();

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

router.get('/termsconditions', (req, res) => {
    res.render('promo_views/termsconditions', {
        layout: 'mainlayout'
    });
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

router.get('/teach_me', (req, res) => {
    res.render('promo_views/teach_me', {
        layout: 'mainlayout'
    });
});


// Export the router
module.exports = router;
