// routes/demoRoutes.js
const express = require('express');
const router = express.Router();
const demoController = require('../../controllers/demoController');

router.get('/book-a-demo', demoController.showDemoForm);
router.post('/book-a-demo', demoController.submitDemoRequest);
router.get('/book-a-demo/success', demoController.showDemoSuccess);

module.exports = router;