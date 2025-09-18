// File: routes/unitformroutes/index.js
const express = require('express');
const router = express.Router();

const Article = require('../../models/unit_models/article');
const Video = require('../../models/unit_models/video');
const Interview = require('../../models/unit_models/interview');
const PromptSet = require('../../models/unit_models/promptset');
const Exercise = require('../../models/unit_models/exercise');
const Template = require('../../models/unit_models/template');

// ✨ NEW: Upcoming model
const Upcoming = require('../../models/unit_models/upcoming');

const unitFormController = require('../../controllers/unitformController');
const ensureAuthenticated = require('../../middleware/ensureAuthenticated');
const isDevelopment = process.env.NODE_ENV !== 'production';
const uploadDocs = require('../../middleware/multerDocuments');
const uploadImg = require('../../middleware/multerImages');
const csrf = require('csurf');
const csrfProtection = csrf();

// Debugging
console.log('ensureAuthenticated:', ensureAuthenticated);
console.log('ensureAuthenticated is a function:', typeof ensureAuthenticated === 'function');
console.log('unitFormController:', unitFormController);

// Shared topics list (kept inline here to mirror your file)
const mainTopics = [
  'Career Development in Technical Services',
  'Soft Skills in Technical Environments',
  'Project Management',
  'Business Development in Technical Services',
  'Finding Projects Before they Become RFPs',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Proposal Management',
  'Proposal Strategy',
  'Designing a Proposal Process',
  'Conducting Color Reviews of Proposals',
  'Storytelling in Technical Marketing',
  'Client Experience',
  'Social Media, Advertising, and Other Mysteries',
  'Pull Marketing',
  'Emotional Intelligence',
  'The Pareto Principle or 80/20',
  'People Before Profit',
  'Non-Technical Roles in Technical Environments',
  'Leadership in Technical Services',
  'Leading Change',
  'Leading Groups on Twennie',
  'The Advantage of Failure',
  'Social Entrepreneurship',
  'Employee Experience',
  'Project Management Software',
  'CRM Platforms',
  'Client Feedback Software',
  'Workplace Culture',
  'Mental Health in Consulting Environments',
  'Remote and Hybrid Work',
  'The Power of Play in the Workplace',
  'Team Building in Consulting',
  'AI in Consulting',
  'AI in Project Management',
  'AI in Learning',
];

// =========================
// Article Form Routes (existing)
// =========================
router.get('/form_article', ensureAuthenticated, unitFormController.getArticleForm);

router.get('/edit_article/:id', ensureAuthenticated, async (req, res) => {
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

    // Word count
    const plainText = article.article_body.replace(/<[^>]*>/g, ' ').trim();
    const wordCount = plainText.split(/\s+/).filter(Boolean).length;

    // Image fallback
    const image = article.image?.url
      ? article.image
      : { public_id: null, url: '/images/default-article.png' };

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
      csrfToken: isDevelopment ? null : req.csrfToken(),
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
  unitFormController.submitArticle
);

// =========================
// ✨ NEW: Upcoming Unit Form Routes
// =========================

// GET: create upcoming
router.get('/form_upcoming', ensureAuthenticated, unitFormController.getUpcomingForm);

// GET: edit upcoming
router.get('/edit_upcoming/:id', ensureAuthenticated, async (req, res) => {
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
      'prompt_set','micro_course','micro_study','peer_coaching'
    ];

    res.render('unit_form_views/form_upcoming', {
      layout: 'unitformlayout',
      data: {
        ...upcoming.toObject(),
        image,
      },
      mainTopics,
      unitTypes,
      csrfToken: isDevelopment ? null : req.csrfToken(),
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
          'prompt_set','micro_course','micro_study','peer_coaching'
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
  unitFormController.submitUpcoming
);

// open correct form prefilled from an upcoming unit
router.get('/prefill_from_upcoming/:unitType/:id',
  ensureAuthenticated,
  unitFormController.prefillFromUpcoming
);



// Video Form Routes
router.get('/form_video', ensureAuthenticated, unitFormController.getVideoForm);

// Edit Video Route
router.get('/edit_video/:id', ensureAuthenticated, async (req, res) => {
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
  
      const mainTopics = [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
      ];
  
      const secondaryTopics = mainTopics.map((topic) => ({
        name: topic,
        selected: video.secondary_topics?.includes(topic) || false,
      }));
  
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
        },
        mainTopics,
        secondaryTopics,
        csrfToken: isDevelopment ? null : req.csrfToken(),
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
  

router.post('/submit_video', ensureAuthenticated, unitFormController.submitVideo);

// Interview Form Routes
router.get('/form_interview', ensureAuthenticated, unitFormController.getInterviewForm);

router.get('/edit_interview/:id', ensureAuthenticated, async (req, res) => {
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
            mainTopics: [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
            ],
            csrfToken: isDevelopment ? null : req.csrfToken(),
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

router.post('/submit_interview', ensureAuthenticated, unitFormController.submitInterview);


// Route to display the template form (Create New)
router.get('/form_template', ensureAuthenticated, csrfProtection, unitFormController.getTemplateForm);


// Route to display the edit form for an existing template
router.get('/edit_template/:id', ensureAuthenticated, async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`Edit form requested for template ID: ${id}`); // Debugging log

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

        const mainTopics = [
            'Career Development in Technical Services',
            'Soft Skills in Technical Environments',
            'Project Management',
            'Business Development in Technical Services',
            'Finding Projects Before they Become RFPs',
            'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
            'Proposal Management',
            'Proposal Strategy',
            'Designing a Proposal Process',
            'Conducting Color Reviews of Proposals',
            'Storytelling in Technical Marketing',
            'Client Experience',
            'Social Media, Advertising, and Other Mysteries',
            'Pull Marketing',
            'Emotional Intelligence',
            'The Pareto Principle or 80/20',
            'People Before Profit',
            'Non-Technical Roles in Technical Environments',
            'Leadership in Technical Services',
            'Leading Change',
            'Leading Groups on Twennie',
            'The Advantage of Failure',
            'Social Entrepreneurship',
            'Employee Experience',
            'Project Management Software',
            'CRM Platforms',
            'Client Feedback Software',
            'Workplace Culture',
            'Mental Health in Consulting Environments',
            'Remote and Hybrid Work',
            'The Power of Play in the Workplace',
            'Team Building in Consulting',
            'AI in Consulting',
            'AI in Project Management',
            'AI in Learning',
        ];

        // Ensure all topics (both selected and unselected) are available
        const secondaryTopics = mainTopics.map((topic) => ({
            name: topic,
            selected: template.secondary_topics?.includes(topic) || false,
        }));

        res.render('unit_form_views/form_template', {
            layout: 'unitformlayout',
            data: template.toObject(), // this makes everything accessible as data.xyz
            mainTopics,
            secondaryTopics,
            csrfToken: isDevelopment ? null : req.csrfToken()
          });
          
    } catch (error) {
        console.error(`Error loading edit form for template ID ${req.params.id}:`, error);
        res.status(500).render('unit_form_views/error', {
            layout: 'unitformlayout',
            title: 'Error',
            errorMessage: 'An error occurred while loading the edit form.',
        });
    }
});

// Route to handle form submission for templates

router.post(
    '/submit_template',
    ensureAuthenticated,
    uploadDocs.array('document_uploads', 3), // ✅ multer first
    csrfProtection,                          // ✅ csrf second
    unitFormController.submitTemplate
  );
  
  
  

router.get('/form_promptset', ensureAuthenticated, unitFormController.getPromptForm);

router.get('/edit_promptset/:id', ensureAuthenticated, async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`Edit form requested for prompt set ID: ${id}`);
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

        res.render('unit_form_views/form_promptset', {
            layout: 'unitformlayout',
            data: {
                ...promptSet.toObject(),
                author: promptSet.author?.id || {
                    name: 'Unknown Author',
                    image: '/images/default-avatar.png',
                },
            },
            mainTopics: [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
            ],
            csrfToken: isDevelopment ? null : req.csrfToken(),
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

router.post('/submit_promptset', ensureAuthenticated, unitFormController.submitPromptSet);

// Exercise Routes
router.get('/form_exercise', ensureAuthenticated, csrfProtection, unitFormController.getExerciseForm);


router.get('/edit_exercise/:id', ensureAuthenticated, csrfProtection, async (req, res) => {
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
  
      res.render('unit_form_views/form_exercise', {
        layout: 'unitformlayout',
        data: {
          ...exercise.toObject(),
          author: exercise.author?.id || {
            name: 'Unknown Author',
            image: '/images/default-avatar.png',
          },
        },
        mainTopics: [
        'Career Development in Technical Services',
        'Soft Skills in Technical Environments',
        'Project Management',
        'Business Development in Technical Services',
        'Finding Projects Before they Become RFPs',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Proposal Management',
        'Proposal Strategy',
        'Designing a Proposal Process',
        'Conducting Color Reviews of Proposals',
        'Storytelling in Technical Marketing',
        'Client Experience',
        'Social Media, Advertising, and Other Mysteries',
        'Pull Marketing',
        'Emotional Intelligence',
        'The Pareto Principle or 80/20',
        'People Before Profit',
        'Non-Technical Roles in Technical Environments',
        'Leadership in Technical Services',
        'Leading Change',
        'Leading Groups on Twennie',
        'The Advantage of Failure',
        'Social Entrepreneurship',
        'Employee Experience',
        'Project Management Software',
        'CRM Platforms',
        'Client Feedback Software',
        'Workplace Culture',
        'Mental Health in Consulting Environments',
        'Remote and Hybrid Work',
        'The Power of Play in the Workplace',
        'Team Building in Consulting',
        'AI in Consulting',
        'AI in Project Management',
        'AI in Learning',
        ],
        csrfToken: req.csrfToken(), // ✅ always pass the token
      });
    } catch (error) {
      console.error(`Error loading edit form for exercise ID ${req.params.id}:`, error);
      res.status(500).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Error',
        errorMessage: 'An error occurred while loading the edit form.',
      });
    }
  });
  

  router.post(
    '/submit_exercise',
    ensureAuthenticated,
    uploadDocs.array('document_uploads', 3), // ✅ multer FIRST
    csrfProtection,                          // ✅ csrf AFTER multer
    unitFormController.submitExercise
  );



// Success Page Route
router.get('/success', ensureAuthenticated, unitFormController.showSuccessPage);

module.exports = router;







