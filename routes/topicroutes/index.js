const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const bytopicController = require('../../controllers/bytopicController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

// Utility to check if a specific view file exists
const viewExists = (viewPath) => {
    const fullPath = path.join(process.cwd(), 'views', `${viewPath}.hbs`);
    console.log(`[viewExists] Resolved path: ${fullPath}`);
    return fs.existsSync(fullPath);
};

router.get('/suggest', ensureAuthenticated, bytopicController.showTopicSuggestionForm);
router.post('/suggest', ensureAuthenticated, bytopicController.submitTopicSuggestion);


// Dynamic rendering of individual static topic pages
router.get('/single_topic_:topicName', (req, res) => {
    const topicName = req.params.topicName;
    const viewPath = `topic_views/single_topic_${topicName}`;

    console.log(`Attempting to render: ${viewPath}`);
    if (viewExists(viewPath)) {
        res.render(viewPath, { layout: 'mainlayout' });
    } else {
        console.error(`View not found: ${viewPath}`);
        res.status(404).send('View template not found');
    }
});

module.exports = router;


