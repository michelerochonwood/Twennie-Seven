// routes/billing.js
const express = require('express');
const router = express.Router();
const billing = require('../../controllers/billingController');

// If you have global CSRF, make sure buttons/forms use tokens for POSTs.
// start/portal can be GET redirects.
router.get('/start', billing.startCheckout);
router.get('/portal', billing.openPortal);
router.post('/sync', billing.manualSeatSync); // optional: admin/test only

module.exports = router;
