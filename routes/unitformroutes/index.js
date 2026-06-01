// File: routes/unitformroutes/index.js
const express = require('express');
const router = express.Router();

const Article = require('../../models/unit_models/article');
const Video = require('../../models/unit_models/video');
const Interview = require('../../models/unit_models/interview');
const PromptSet = require('../../models/unit_models/promptset');
const Exercise = require('../../models/unit_models/exercise');
const Template = require('../../models/unit_models/template');
const Mission = require('../../models/unit_models/mission');

// ✨ NEW: Upcoming model
const Upcoming = require('../../models/unit_models/upcoming');
const Nugget = require('../../models/unit_models/nugget');

const unitFormController = require('../../controllers/unitformController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');

const uploadDocs = require('../../middleware/multerDocuments');
const uploadImg = require('../../middleware/multerImages');
const csrf = require('csurf');
const csrfProtection = csrf();
const ensureCanContribute = require('../../middleware/ensureCanContribute');
const unitviewController = require('../../controllers/unitviewController');
// Debugging
console.log('ensureAuthenticated:', ensureAuthenticated);
console.log('ensureAuthenticated is a function:', typeof ensureAuthenticated === 'function');
console.log('unitFormController:', unitFormController);




// Shared topics list (kept inline here to mirror your file)
const mainTopics = [
  'AI in Adult Learning',
  'AI in Consulting',
  'AI in Project Management',
  'Analytics in Project Management',
  'Business Development in Technical Services',
  'Business Development Metrics',
  'Candid Communication',
  'Career Development in Technical Services',
  'Client Experience',
  'Client Feedback Software',
  'Client Interactions',
  'Closing a Project Strategically',
  'Conducting Color Reviews of Proposals',
  'Conducting Market Research',
  'Cross Selling in Multi-Disciplinary Firms',
  'Creativity and Innovation',
  'CRM Software',
  'Cures for Operational Headaches',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Making Safety a Part of Your Culture',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
  'Never Let Good Data Get Away Business Development',
  'Never Let Good Data Get Away Project Management',
  'Non-Technical Roles in Technical Environments',
  'People Before Profit',
  'Program Management',
  'Project Management',
  'Project Management Software',
  'Proposal Management',
  'Proposal Strategy',
  'Pull Marketing',
  'Pursuing the Right Projects for Your Firm and Your Team',
  'Remote and Hybrid Work',
  'Rescuing a Project That Has Gone Off the Rails',
  'Risk Management',
  'Social Entrepreneurship',
  'Social Media, Advertising, and Other Mysteries',
  'Soft Skills in Technical Environments',
  'Storytelling in Technical Marketing',
  'Team Building in Technical Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'UnCommoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
];

function buildSecondaryTopicOptions(selectedTopics = []) {
  const normalizedSelected = Array.isArray(selectedTopics)
    ? selectedTopics.filter(topic => typeof topic === 'string' && topic.trim() !== '')
    : typeof selectedTopics === 'string' && selectedTopics.trim() !== ''
      ? [selectedTopics.trim()]
      : [];

  return mainTopics.map((topic) => ({
    name: topic,
    selected: normalizedSelected.includes(topic),
  }));
}

router.get('/form_nugget', ensureAuthenticated, ensureCanContribute, unitFormController.getNuggetForm);

router.get('/edit_nugget/:id', ensureAuthenticated, csrfProtection, async (req, res) => {

  try {
    const { id } = req.params;
    console.log(`Edit form requested for nugget ID: ${id}`);

    const nugget = await Nugget.findById(id).populate({
      path: 'createdBy',
      model: 'Member',
      select: 'name profileImage',
    });

    if (!nugget) {
      console.warn(`Nugget with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Nugget Not Found',
        errorMessage: `The nugget with ID ${id} does not exist.`,
      });
    }

    res.render('unit_form_views/form_nugget', {
      layout: 'unitformlayout',
      data: {
        ...nugget.toObject(),
        creator: {
          name: nugget.createdBy?.name || 'Unknown Creator',
          image: nugget.createdBy?.profileImage || '/images/default-avatar.png',
        },
      },
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for nugget ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the nugget edit form.',
    });
  }
});

router.post('/submit_nugget', ensureAuthenticated, csrfProtection, unitFormController.submitNugget);


// =========================
// Article Form Routes (existing)
// =========================



router.get('/form_article', ensureAuthenticated, ensureCanContribute, unitFormController.getArticleForm);

router.post(
  '/submit_article',
  ensureAuthenticated,
  (req, res, next) => {
    uploadImg.single('image')(req, res, function (err) {
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).render('unit_form_views/form_article', {
          layout: 'unitformlayout',
          data: req.body,
          errorMessage: 'Image exceeds the 5MB file size limit.',
          mainTopics,
        });
      }
      next(err);
    });
  },
  ensureCanContribute,
  csrfProtection,
  unitFormController.submitArticle
);

router.get('/edit_article/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Edit form requested for article ID: ${id}`);

    const article = await Article.findById(id).populate({
      path: 'author.id',
      model: 'Member',
      select: 'name profileImage',
    });

    if (!article) {
      console.warn(`Article with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Article Not Found',
        errorMessage: `The article with ID ${id} does not exist.`,
      });
    }

    const plainText = (article.article_body || '').replace(/<[^>]*>/g, ' ').trim();
    const wordCount = plainText.split(/\s+/).filter(Boolean).length;

    const image = article.image?.url
      ? article.image
      : { public_id: null, url: '/images/default-article.png' };

    const secondaryTopics = buildSecondaryTopicOptions(article.secondary_topics);

    res.render('unit_form_views/form_article', {
      layout: 'unitformlayout',
      data: {
        ...article.toObject(),
        image,
        author: {
          name: article.author?.id?.name || 'Unknown Author',
          image: article.author?.id?.profileImage || '/images/default-avatar.png',
        },
      },
      word_count: wordCount,
      mainTopics,
      secondaryTopics,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for article ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the edit form.',
    });
  }
});

// =========================
// ✨ NEW: Upcoming Unit Form Routes
// =========================

// GET: create upcoming

router.get(
  '/form_upcoming',
  ensureAuthenticated,
  ensureCanContribute,
  unitFormController.getUpcomingForm
);

// GET: edit upcoming
router.get('/edit_upcoming/:id', ensureAuthenticated, csrfProtection, async (req, res) => {

  try {
    const { id } = req.params;
    console.log(`Edit form requested for upcoming ID: ${id}`);

    const upcoming = await Upcoming.findById(id);
    if (!upcoming) {
      console.warn(`Upcoming with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Upcoming Unit Not Found',
        errorMessage: `The upcoming unit with ID ${id} does not exist.`,
      });
    }

    // Image fallback
    const image = upcoming.image?.url
      ? upcoming.image
      : { public_id: null, url: '/images/default-upcoming.png' };

    // Unit types for select
const unitTypes = [
  'article','video','interview','exercise','template',
  'promptset','nugget','mission'
];

    res.render('unit_form_views/form_upcoming', {
      layout: 'unitformlayout',
      data: {
        ...upcoming.toObject(),
        image,
      },
      mainTopics,
      unitTypes,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for upcoming ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the edit form.',
    });
  }
});

// POST: create/update upcoming (mirror image-size guard)
router.post(
  '/submit_upcoming',
  ensureAuthenticated,
  (req, res, next) => {
    uploadImg.single('image')(req, res, function (err) {
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        const unitTypes = [
          'article','video','interview','exercise','template',
          'promptset','nugget','mission'
        ];
        return res.status(400).render('unit_form_views/form_upcoming', {
          layout: 'unitformlayout',
          data: req.body,
          errorMessage: 'Image exceeds the 5MB file size limit.',
          mainTopics,
          unitTypes,
        });
      }
      next(err);
    });
  },
  csrfProtection,
  ensureCanContribute,
  unitFormController.submitUpcoming
);


// open correct form prefilled from an upcoming unit
router.get('/prefill_from_upcoming/:unitType/:id',
  ensureAuthenticated,
  unitFormController.prefillFromUpcoming
);



// Video Form Routes
router.get('/form_video', ensureAuthenticated, ensureCanContribute, unitFormController.getVideoForm);

// Edit Video Route
router.get('/edit_video/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Edit form requested for video ID: ${id}`);

    const video = await Video.findById(id).populate({
      path: 'author.id',
      model: 'Member',
      select: 'name profileImage',
    });

    if (!video) {
      console.warn(`Video with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Video Not Found',
        errorMessage: `The video with ID ${id} does not exist.`,
      });
    }

    const secondaryTopics = buildSecondaryTopicOptions(video.secondary_topics);

    res.render('unit_form_views/form_video', {
      layout: 'unitformlayout',
      data: {
        _id: video._id.toString(),
        video_title: video.video_title,
        short_summary: video.short_summary,
        full_summary: video.full_summary,
        video_content: video.video_content,
        main_topic: video.main_topic,
        secondary_topics: video.secondary_topics,
        sub_topic: video.sub_topic,
        clarify_topic: video.clarify_topic,
        produce_deliverables: video.produce_deliverables,
        new_ideas: video.new_ideas,
        engaging: video.engaging,
        permission: video.permission,
        visibility: video.visibility,
        author: {
          name: video.author?.id?.name || 'Unknown Author',
          image: video.author?.id?.profileImage || '/images/default-avatar.png',
        },
      },
      mainTopics,
      secondaryTopics,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for video ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the edit form.',
    });
  }
});
  

router.post('/submit_video', ensureAuthenticated, csrfProtection, unitFormController.submitVideo);


// Interview Form Routes
router.get(
  '/form_interview',
  ensureAuthenticated,
  ensureCanContribute,
  unitFormController.getInterviewForm
);

router.get('/edit_interview/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Edit form requested for interview ID: ${id}`);

    const interview = await Interview.findById(id).populate({
      path: 'author.id',
      model: 'Member',
      select: 'name profileImage',
    });

    if (!interview) {
      console.warn(`Interview with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Interview Not Found',
        errorMessage: `The interview with ID ${id} does not exist.`,
      });
    }

    const secondaryTopics = buildSecondaryTopicOptions(interview.secondary_topics);

    const authorData = interview.author?.id
      ? {
          name: interview.author.id.name || 'Unknown Author',
          image: interview.author.id.profileImage || '/images/default-avatar.png',
        }
      : {
          name: 'Unknown Author',
          image: '/images/default-avatar.png',
        };

    res.render('unit_form_views/form_interview', {
      layout: 'unitformlayout',
      data: {
        ...interview.toObject(),
        author: authorData,
      },
      mainTopics,
      secondaryTopics,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for interview ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the edit form.',
    });
  }
});

router.post('/submit_interview', ensureAuthenticated, csrfProtection, unitFormController.submitInterview);



// =========================
// Template Routes
// =========================

// Create template form
router.get(
  '/form_template',
  ensureAuthenticated,
  ensureCanContribute,
  csrfProtection,
  unitFormController.getTemplateForm
);


// Edit template form
router.get(
  '/edit_template/:id',
  ensureAuthenticated,
  csrfProtection,
  async (req, res) => {
    try {
      const { id } = req.params;

      console.log(`Edit form requested for template ID: ${id}`);

      const template = await Template.findById(id).populate({
        path: 'author.id',
        model: 'Member',
        select: 'name profileImage',
      });

      if (!template) {
        console.warn(`Template with ID ${id} not found.`);

        return res.status(404).render('unit_form_views/error', {
          layout: 'unitformlayout',
          title: 'Template Not Found',
          errorMessage: `The template with ID ${id} does not exist.`,
        });
      }

      const secondaryTopics = buildSecondaryTopicOptions(template.secondary_topics);

      return res.render('unit_form_views/form_template', {
        layout: 'unitformlayout',

        data: {
          ...template.toObject(),

          author: {
            name: template.author?.id?.name || 'Unknown Author',
            image:
              template.author?.id?.profileImage ||
              '/images/default-avatar.png',
          },
        },

        mainTopics,
        secondaryTopics,
        csrfToken: req.csrfToken(),
      });

    } catch (error) {
      console.error(
        `Error loading edit form for template ID ${req.params.id}:`,
        error
      );

      return res.status(500).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading the edit form.',
      });
    }
  }
);


// Submit template form
router.post(
  '/submit_template',
  ensureAuthenticated,
  uploadDocs.fields([
    { name: 'template_pdf', maxCount: 1 }
  ]),
  csrfProtection,
  ensureCanContribute,
  unitFormController.submitTemplate
);
  
  
  

router.get(
  '/form_promptset',
  ensureAuthenticated,
  ensureCanContribute,
  unitFormController.getPromptForm
);

router.get('/edit_promptset/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Edit form requested for prompt set ID: ${id}`);

    const frequencies = ['daily', 'weekly', 'monthly', 'quarterly'];

    const characteristics = [
      'investigative',
      'reflective',
      'strategic',
      'educational',
      'motivational',
      'thought-provoking',
      'transformative',
      'fun',
      'hilarious',
      'silly',
      'competitive',
      'restorative',
      'energizing',
      'relationship-building',
      'team building',
      'stress-relieving',
      'insightful',
      'calming',
      'reassuring',
      'encouraging',
      'creative',
      'imaginative',
      'heart-warming',
      'other',
    ];

    const promptSet = await PromptSet.findById(id).populate({
      path: 'author.id',
      model: 'Member',
      select: 'name profileImage',
    });

    if (!promptSet) {
      console.warn(`Prompt set with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Prompt Set Not Found',
        errorMessage: `The prompt set with ID ${id} does not exist.`,
      });
    }

    const secondaryTopics = buildSecondaryTopicOptions(promptSet.secondary_topics);

    const author = promptSet.author?.id
      ? {
          name: promptSet.author.id.name || 'Unknown Author',
          image: promptSet.author.id.profileImage || '/images/default-avatar.png',
        }
      : {
          name: 'Unknown Author',
          image: '/images/default-avatar.png',
        };

    res.render('unit_form_views/form_promptset', {
      layout: 'unitformlayout',
      data: {
        ...promptSet.toObject(),
        author,
      },
      mainTopics,
      secondaryTopics,
      frequencies,
      characteristics,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for prompt set ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the edit form.',
    });
  }
});


router.post('/submit_promptset', ensureAuthenticated, csrfProtection, unitFormController.submitPromptSet);


// =========================
// Exercise Routes
// =========================

// Create exercise form
router.get(
  '/form_exercise',
  ensureAuthenticated,
  ensureCanContribute,
  csrfProtection,
  unitFormController.getExerciseForm
);

// Edit exercise form
router.get(
  '/edit_exercise/:id',
  ensureAuthenticated,
  csrfProtection,
  async (req, res) => {
    try {
      const { id } = req.params;

      console.log(`Edit form requested for exercise ID: ${id}`);

      const exercise = await Exercise.findById(id).populate({
        path: 'author.id',
        model: 'Member',
        select: 'name profileImage',
      });

      if (!exercise) {
        return res.status(404).render('unit_form_views/error', {
          layout: 'unitformlayout',
          title: 'Exercise Not Found',
          errorMessage: `The exercise with ID ${id} does not exist.`,
        });
      }

      const secondaryTopics = buildSecondaryTopicOptions(exercise.secondary_topics);

      return res.render('unit_form_views/form_exercise', {
        layout: 'unitformlayout',
        data: {
          ...exercise.toObject(),
          author: {
            name: exercise.author?.id?.name || 'Unknown Author',
            image: exercise.author?.id?.profileImage || '/images/default-avatar.png',
          },
        },
        mainTopics,
        secondaryTopics,
        csrfToken: req.csrfToken(),
      });

    } catch (error) {
      console.error(`Error loading edit form for exercise ID ${req.params.id}:`, error);

      return res.status(500).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading the edit form.',
      });
    }
  }
);

// Submit exercise form
router.post(
  '/submit_exercise',
  ensureAuthenticated,
  uploadDocs.array('document_uploads', 3),
  csrfProtection,
  ensureCanContribute,
  unitFormController.submitExercise
);
  // =========================
// Mission Form Routes
// =========================

// GET: create mission
router.get(
  '/form_mission',
  ensureAuthenticated,
  ensureCanContribute,
  csrfProtection,
  unitFormController.getMissionForm
);

// GET: edit mission
router.get('/edit_mission/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Edit form requested for mission ID: ${id}`);

    const mission = await Mission.findById(id);
    if (!mission) {
      console.warn(`Mission with ID ${id} not found.`);
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Mission Not Found',
        errorMessage: `The mission with ID ${id} does not exist.`,
      });
    }

    res.render('unit_form_views/form_mission', {
      layout: 'unitformlayout',
      data: mission.toObject(),
      mainTopics,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error(`Error loading edit form for mission ID ${req.params.id}:`, error);
    res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the mission edit form.',
    });
  }
});

// POST: create/update mission
router.post(
  '/submit_mission',
  ensureAuthenticated,
  csrfProtection,
  unitFormController.submitMission
);




// Success Page Route
router.get('/success', ensureAuthenticated, unitFormController.showSuccessPage);

module.exports = router;







