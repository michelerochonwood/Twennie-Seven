// routes/archiveRoutes.js
const express = require('express');
const router = express.Router();
const archiveController = require('../../controllers/archiveController');

// tag-based archive action
router.post('/', archiveController.archiveUnit);

// completed prompt set archive action
router.post('/completed-promptset', archiveController.archiveCompletedPromptSet);

// archive views
router.get('/leader', archiveController.renderLeaderArchive);
router.get('/groupmember', archiveController.renderGroupMemberArchive);

// later:
// router.get('/member', archiveController.renderMemberArchive);

module.exports = router;