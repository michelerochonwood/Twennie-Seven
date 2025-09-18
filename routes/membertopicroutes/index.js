const express = require('express');
const router = express.Router();

// Route to serve member topic views dynamically
router.get('/:viewName', (req, res) => {
    const { viewName } = req.params;

    // Security check: Prevent directory traversal
    if (!viewName.startsWith('single_topic_')) {
        console.error(`Invalid view requested: ${viewName}`);
        return res.status(400).send('Invalid topic view.');
    }

    res.render(`topic_views/${viewName}`, {
        layout: 'mainlayout', // Adjust layout if needed
        title: 'Member Topic Details'
    });
});

module.exports = router;
