const express = require('express');
const router = express.Router();
const promptSetRegistrationController = require('../../controllers/promptsetregistrationController');
const isAuthenticated = require('../../middleware/ensureAuthenticated'); // Middleware to check authentication

// 🔹 Register for a prompt set
router.post('/register', isAuthenticated, promptSetRegistrationController.registerPromptSet);

// 🔹 Fetch all registered prompt sets for the logged-in user
router.get('/registered', isAuthenticated, promptSetRegistrationController.getRegisteredPromptSets);

// 🔹 Unregister from a prompt set
router.delete('/unregister/:registrationId', isAuthenticated, promptSetRegistrationController.unregisterPromptSet);

// 🔹 Track progress updates for prompt sets
router.post('/update-progress', isAuthenticated, promptSetRegistrationController.updateProgress);

// 🔹 Render success page after registering for a prompt set
router.get('/promptsetregistersuccess', (req, res) => {
    res.render('promptsetregistersuccess', {
        layout: 'unitviewlayout',
        promptset_title: req.query.title,
        frequency: req.query.frequency,
        completion_date: req.query.completion_date,
        dashboard: req.query.dashboard
    });
});

module.exports = router;
