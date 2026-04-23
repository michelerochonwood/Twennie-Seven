// routes/archiveRoutes.js
const express = require('express');
const router = express.Router();
const archiveController = require('../controllers/archiveController');

// archive action
router.post('/', archiveController.archiveUnit);

// archive views
router.get('/leader', archiveController.renderLeaderArchive);

// later:
// router.get('/groupmember', archiveController.renderGroupMemberArchive);
// router.get('/member', archiveController.renderMemberArchive);

module.exports = router;