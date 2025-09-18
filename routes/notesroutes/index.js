const express = require('express');
const router = express.Router();
const notesController = require('../../controllers/notesController');

// Route to submit a note (POST)
router.post('/submit', notesController.createNote);

// Get all notes for leaders (GET)
router.get('/leader-notes', notesController.getNotesByLeader);

// Get all notes for a specific group member (GET)
router.get('/my-notes', notesController.getNotesByGroupMember);

router.get('/unitnotessuccess', (req, res) => {
    res.render('unit_views/unitnotessuccess');
});

module.exports = router;
