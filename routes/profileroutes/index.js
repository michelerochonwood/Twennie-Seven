const express = require("express");
const router = express.Router();
const profileController = require("../../controllers/profileController");
const ensureAuthenticated = require("../../middleware/ensureAuthenticated");
const uploadImages = require("../../middleware/multerImages"); // ✅ updated import




// ✅ Public Profile Routes
router.get("/member/:id", profileController.viewMemberProfile);
router.get("/leader/:id", profileController.viewLeaderProfile);
router.get("/groupmember/:id", profileController.viewGroupMemberProfile);
router.get("/group/:id", profileController.viewGroupProfile);

// ✅ Private Profile Edit Routes (with image upload)
router.get("/member/:id/edit", ensureAuthenticated, profileController.editMemberProfile);
router.post("/member/:id/update", ensureAuthenticated, uploadImages.single("profileImage"), profileController.updateMemberProfile);

router.get("/leader/:id/edit", ensureAuthenticated, profileController.editLeaderProfile);
router.post("/leader/:id/update", ensureAuthenticated, uploadImages.single("profileImage"), profileController.updateLeaderProfile);

router.get("/groupmember/:id/edit", ensureAuthenticated, profileController.editGroupMemberProfile);
router.post("/groupmember/:id/update", ensureAuthenticated, uploadImages.single("profileImage"), profileController.updateGroupMemberProfile);

router.get("/group/:id/edit", ensureAuthenticated, profileController.editGroupProfile);
router.post("/group/:id/update", ensureAuthenticated, uploadImages.single("profileImage"), profileController.updateGroupProfile);

router.get("/survey", ensureAuthenticated, profileController.showProfileSurveyForm);
router.post("/survey/submit", ensureAuthenticated, profileController.submitProfileSurvey);

// ✅ Optional test upload endpoint
router.post('/upload-profile', uploadImages.single('profileImage'), async (req, res) => {
  try {
    const buffer = req.file.buffer;
    const base64 = buffer.toString('base64');
    const dataUri = `data:${req.file.mimetype};base64,${base64}`;

    const { uploader } = require('../../utils/cloudinary'); // ✅ updated access to uploader
    const result = await uploader.upload(dataUri, {
      folder: 'twennie_profiles',
    });

    res.status(200).json({ imageUrl: result.secure_url });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).send('Image upload failed');
  }
});

module.exports = router;



















