// routes/demoRoutes.js
const express = require('express');
const router = express.Router();
const demoController = require('../controllers/demoController');

router.get('/book-a-demo', demoController.showDemoForm);
router.post('/book-a-demo', demoController.submitDemoRequest);

module.exports = router;