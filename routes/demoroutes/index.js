// routes/demoRoutes.js
const express = require('express');
const router = express.Router();
const demoController = require('../../controllers/demoController');

router.get('/book-a-demo', demoController.showDemoForm);
router.post('/book-a-demo', demoController.submitDemoRequest);

router.get('/book-a-demo/success', (req, res) => {
res.render('promo_views/demo_success', {
layout: 'mainlayout'
});
});

module.exports = router;