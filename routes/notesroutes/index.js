const express = require('express');
const router = express.Router();
const notesController = require('../../controllers/notesController');

// Route to submit a note (POST)
router.post('/submit', notesController.createNote);

// Get all notes for leaders (GET)
router.get('/leader-notes', notesController.getNotesByLeader);

// Get my notes (group member or individual member)
router.get('/my-notes', (req, res, next) => {
  const membershipType = req.user?.membershipType || req.session?.user?.membershipType;

  if (membershipType === 'group_member') {
    return notesController.getNotesByGroupMember(req, res, next);
  }

  if (membershipType === 'member') {
    return notesController.getNotesByMember(req, res, next);
  }

  return res.status(403).send('Unauthorized: This notes view is not available for your account type.');
});

router.get('/unitnotessuccess', (req, res) => {
  res.render('unit_views/unitnotessuccess');
});

module.exports = router;
