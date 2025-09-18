const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const PromptSet = require('../models/unit_models/promptset');
const Template = require('../models/unit_models/template');
const Exercise = require('../models/unit_models/exercise');
const MicroStudy = require('../models/unit_models/microstudy');
const MicroCourse = require('../models/unit_models/microcourse');
const { uploader } = require('../utils/cloudinary');
const { Readable } = require('stream');
const sanitizeHtml = require('sanitize-html');
const Upcoming = require('../models/unit_models/upcoming'); // ← add this
const Tag = require('../models/tag'); 
console.log('unitFormController loaded');



// Environment check for development mode
const isDevelopment = process.env.NODE_ENV !== 'production';

// Migrate tags from 'upcoming' → new unit, then delete the upcoming doc.
// Called by each submit handler IFF fromUpcomingId exists.
async function migrateAndDeleteUpcoming({ fromUpcomingId, toItemId, toUnitType }) {
  if (!fromUpcomingId || !toItemId || !toUnitType) return;

  try {
    const { modifiedCount } = await Tag.migrateAssociatedUnits({
      fromItemId: fromUpcomingId,
      toItemId,
      toUnitType, // use exact strings your app already uses: 'article','video','promptset', etc.
      // fromUnitType defaults to 'upcoming' in the Tag static
    });
    console.log(`🔁 migrated ${modifiedCount} tag association(s) from upcoming → ${toUnitType} ${toItemId}`);
  } catch (e) {
    console.error('Tag migration failed (non-fatal):', e);
  }

  try {
    await Upcoming.findByIdAndDelete(fromUpcomingId);
    console.log(`🧹 deleted upcoming ${fromUpcomingId}`);
  } catch (e) {
    console.error('Failed to delete upcoming (non-fatal):', e);
  }
}

// Helper function to safely get CSRF token
function getCsrfToken(req) {
  return req.csrfToken ? req.csrfToken() : null;
}



const createGetFormHandler = (unitType, viewPath) => (req, res) => {
  console.log(`🛡 Rendering ${unitType} form. CSRF available:`, typeof req.csrfToken === 'function');

    try {
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

        res.render(`unit_form_views/${viewPath}`, {
          layout: 'unitformlayout',
          unitType,
          mainTopics,
          data: {},
          csrfToken: getCsrfToken(req),
      });
    } catch (error) {
        console.error(`Error rendering form for ${unitType}:`, error);
        res.status(500).send(`Error rendering form for ${unitType}.`);
    }
};

const unitFormController = {
    // Explicitly created handlers
    getArticleForm: createGetFormHandler('article', 'form_article'),
    getVideoForm: createGetFormHandler('video', 'form_video'),
    getInterviewForm: createGetFormHandler('interview', 'form_interview'),
    getPromptForm: createGetFormHandler('promptset', 'form_promptset'),
    getExerciseForm: createGetFormHandler('exercise', 'form_exercise'),
    getTemplateForm: createGetFormHandler('template', 'form_template'),
    getMicroCourseForm: createGetFormHandler('microcourse', 'form_microcourse'),
    getMicroStudyForm: createGetFormHandler('microstudy', 'form_microstudy'),

    // POST Handlers with Validation
    submitUnit: (Model, unitType, validateFunction) => async (req, res) => {
        

        try {
            console.log(`Received POST request for ${unitType}:`, req.body);
    
            const errors = validateFunction(req.body);
            if (errors.length > 0) {
                return res.render(`unit_form_views/form_${unitType}`, {
                    layout: 'unitformlayout',
                    data: req.body,
                    errors,
                    csrfToken: isDevelopment ? null : req.csrfToken(),
                });
            }
    
            const unitData = {
                author: {
                    id: req.user._id,
                },
                topic: req.body.topic || 'No topic specified', 
                ...req.body,
            };
    
            const unit = req.body._id
                ? await Model.findByIdAndUpdate(req.body._id, unitData, { new: true })
                : await Model.create(unitData);
    
            console.log(`Saved ${unitType} successfully:`, unit);
    
            res.render('unit_form_views/unit_success', {
                layout: 'unitformlayout',
                unitType,
                unit,
                csrfToken: isDevelopment ? null : req.csrfToken(),
            });
        } catch (error) {
            console.error(`${unitType} submission error:`, error);
            res.status(500).render('unit_form_views/error', {
                layout: 'unitformlayout',
                title: 'Error',
                errorMessage: 'An error occurred while submitting the unit.',
            });
        }
    },
    

    // Success Page Handler
    showSuccessPage: async (req, res) => {

        const { unitType, id, error } = req.query;

        try {
            let unit = null;
            if (id) {
                const Model = {
                    article: Article,
                    video: Video,
                    interview: Interview,
                    promptset: PromptSet,
                    template: Template,
                    exercise: Exercise,
                    microstudy: MicroStudy,
                    microcourse: MicroCourse,
                }[unitType];

                unit = await Model.findById(id);
                console.log(`Fetched ${unitType} for success page:`, unit);
            }

            res.render('unit_form_views/unit_success', {
                layout: 'unitformlayout',
                unitType,
                unit,
                error,
                csrfToken: isDevelopment ? null : req.csrfToken(),
            });
        } catch (fetchError) {
            console.error(`Error fetching ${unitType} details for success page:`, fetchError);
            res.status(500).render('unit_form_views/error', {
                layout: 'unitformlayout',
                unitType,
                error: 'Unable to fetch unit details.',
                csrfToken: isDevelopment ? null : req.csrfToken(),
            });
        }
    },


// ↓ add alongside your explicit "getXForm" handlers
getUpcomingForm: (req, res) => {
  console.log('🛡 Rendering upcoming form. CSRF available:', typeof req.csrfToken === 'function');

  try {
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

    const unitTypes = [
      'article','video','interview','exercise','template',
      'prompt_set','micro_course','micro_study','peer_coaching'
    ];

    return res.render('unit_form_views/form_upcoming', {
      layout: 'unitformlayout',
      unitType: 'upcoming',
      mainTopics,
      unitTypes,
      data: {},
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error rendering form for upcoming:', error);
    return res.status(500).send('Error rendering form for upcoming.');
  }
},


// ---- submitUpcoming (drop-in) ----
submitUpcoming: async (req, res) => {
  try {
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

    if (!req.user && !req.session?.user) {
      return res.status(401).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Unauthorized',
        errorMessage: 'Please log in to submit an upcoming unit.',
      });
    }

    // Pull fields
    const {
      _id,
      title,
      unit_type,
      main_topic,
      secondary_topics,
      sub_topic,
      teaser,
      long_teaser,
      projected_release_at,
      status,
      visibility,
      is_featured,
      priority,
    } = req.body;

    // Basic required validations
    const errors = [];
    if (!title?.trim()) errors.push('Title is required.');
    if (!unit_type) errors.push('Unit type is required.');
    if (!main_topic) errors.push('Main topic is required.');
    if (!projected_release_at) errors.push('Projected release date is required.');

    if (errors.length) {
      return res.status(400).render('unit_form_views/form_upcoming', {
        layout: 'unitformlayout',
        unitType: 'upcoming',
        data: req.body,
        errors,
        mainTopics,
        unitTypes: [
          'article','video','interview','exercise','template',
          'prompt_set','micro_course','micro_study','peer_coaching'
        ],
        csrfToken: getCsrfToken(req),
      });
    }

    // Normalize optional secondary topic into array
    const parsedSecondaryTopics =
      Array.isArray(secondary_topics)
        ? secondary_topics.filter(Boolean)
        : (secondary_topics && typeof secondary_topics === 'string' && secondary_topics.trim() !== '')
          ? [secondary_topics]
          : [];

    // Constrain status to allowed values
    const ALLOWED_STATUS = ['in production', 'released', 'cancelled'];
    const safeStatus = ALLOWED_STATUS.includes(status) ? status : 'in production';

    // Creator (for ownership)
    const creatorId = (req.user?._id || req.session?.user?.id) || null;
    const creatorModel = (req.user?.membershipType || req.session?.user?.membershipType) || null;

    const payload = {
      title: title.trim(),
      unit_type,
      main_topic,
      secondary_topics: parsedSecondaryTopics,
      sub_topic: sub_topic?.trim() || undefined,
      teaser: teaser?.trim() || undefined,
      long_teaser: long_teaser?.trim() || undefined,
      projected_release_at: new Date(projected_release_at),
      status: safeStatus,
      visibility: visibility || 'all_members',
      is_featured: !!is_featured,
      priority: Number.isFinite(Number(priority)) ? Number(priority) : 0,
    };

    // Handle image upload (optional)
    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = uploader.upload_stream(
          { folder: 'twennie_upcoming', resource_type: 'image' },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        const readable = new Readable();
        readable._read = () => {};
        readable.push(req.file.buffer);
        readable.push(null);
        readable.pipe(stream);
      });

      payload.image = {
        public_id: uploadResult.public_id,
        url: uploadResult.secure_url,
      };
    }

    // Fallback image if none provided (create mode only or missing existing)
    if (!payload.image && !_id) {
      payload.image = { public_id: null, url: '/images/default-upcoming.png' };
    }

    let upcoming;

    if (_id) {
      // Edit (do not overwrite an existing creator; backfill if missing)
      upcoming = await Upcoming.findByIdAndUpdate(_id, payload, {
        new: true,
        runValidators: true,
      });
      if (!upcoming) {
        return res.status(404).render('unit_form_views/error', {
          layout: 'unitformlayout',
          title: 'Not Found',
          errorMessage: 'Upcoming unit not found for editing.',
        });
      }

      if (!upcoming.createdBy && creatorId) {
        upcoming.createdBy = creatorId;
        if (creatorModel) upcoming.createdByModel = creatorModel;
        await upcoming.save();
      }

      console.log(`Upcoming with ID ${_id} updated successfully.`);
    } else {
      // Create — stamp creator for "my library units"
      if (creatorId) {
        payload.createdBy = creatorId;
        if (creatorModel) payload.createdByModel = creatorModel;
      }
      upcoming = new Upcoming(payload);
      await upcoming.save();
      console.log('New upcoming unit created successfully.');
    }

    // Success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'upcoming',
      unit: upcoming,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    console.error('Error submitting upcoming unit:', error);

    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: error.message || 'An error occurred while submitting the upcoming unit.',
    });
  }
},

// ---- prefillFromUpcoming (drop-in) ----
prefillFromUpcoming: async (req, res) => {
  try {
    const { unitType, id } = req.params;
    const upcoming = await Upcoming.findById(id).lean();
    if (!upcoming) {
      return res.status(404).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Not Found',
        errorMessage: 'Upcoming unit not found.'
      });
    }

    const mainTopics = [
      'Career Development in Technical Services','Soft Skills in Technical Environments','Project Management',
      'Business Development in Technical Services','Finding Projects Before they Become RFPs',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value','Proposal Management','Proposal Strategy',
      'Designing a Proposal Process','Conducting Color Reviews of Proposals','Storytelling in Technical Marketing',
      'Client Experience','Social Media, Advertising, and Other Mysteries','Pull Marketing','Emotional Intelligence',
      'The Pareto Principle or 80/20','People Before Profit','Non-Technical Roles in Technical Environments',
      'Leadership in Technical Services','Leading Change','Leading Groups on Twennie','The Advantage of Failure',
      'Social Entrepreneurship','Employee Experience','Project Management Software','CRM Platforms',
      'Client Feedback Software','Workplace Culture','Mental Health in Consulting Environments','Remote and Hybrid Work',
      'The Power of Play in the Workplace','Team Building in Consulting','AI in Consulting','AI in Project Management','AI in Learning',
    ];

    // Image fallback
    const image = upcoming.image?.url ? upcoming.image : { public_id: null, url: '/images/default-upcoming.png' };

    if (unitType === 'article') {
      return res.render('unit_form_views/form_article', {
        layout: 'unitformlayout',
        mainTopics,
        data: {
          article_title: upcoming.title,
          main_topic: upcoming.main_topic,
          secondary_topics: (upcoming.secondary_topics || [])[0] || '',
          sub_topic: upcoming.sub_topic,
          short_summary: upcoming.teaser,
          full_summary: upcoming.long_teaser,
          visibility: upcoming.visibility,
          image
        },
        fromUpcomingId: upcoming._id.toString(),
        csrfToken: req.csrfToken?.()
      });
    }

    if (unitType === 'video') {
      return res.render('unit_form_views/form_video', {
        layout: 'unitformlayout',
        mainTopics,
        data: {
          video_title: upcoming.title,
          main_topic: upcoming.main_topic,
          secondary_topics: (upcoming.secondary_topics || [])[0] || '',
          sub_topic: upcoming.sub_topic,
          short_summary: upcoming.teaser,
          full_summary: upcoming.long_teaser,
          visibility: upcoming.visibility,
          image
        },
        fromUpcomingId: upcoming._id.toString(),
        csrfToken: req.csrfToken?.()
      });
    }

    if (unitType === 'promptset') {
      const secondaryTopics = mainTopics.slice();
      const characteristics = [
        'educational','motivational','provocative','fun','hilarious','silly','competitive','restorative','energizing',
        'relationship-building','team building','stress-relieving','insightful','calming','reassuring','encouraging',
        'creative','imaginative','heart-warming','other'
      ];
      const frequencies = ['daily', 'weekly', 'monthly', 'quarterly'];

      return res.render('unit_form_views/form_promptset', {
        layout: 'unitformlayout',
        data: {
          main_topic: upcoming.main_topic,
          secondary_topics: (upcoming.secondary_topics || [])[0] || '',
          sub_topic: upcoming.sub_topic,
          visibility: upcoming.visibility,
        },
        mainTopics,
        secondaryTopics,
        characteristics,
        frequencies,
        fromUpcomingId: upcoming._id.toString(),
        csrfToken: req.csrfToken?.()
      });
    }

    return res.status(400).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Unsupported',
      errorMessage: `Prefill for unit type "${unitType}" is not configured yet.`
    });
  } catch (err) {
    console.error('prefillFromUpcoming error:', err);
    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'Could not prefill from upcoming.'
    });
  }
},







submitArticle: async (req, res) => {
  try {
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

    console.log('Incoming file:', req.file);

    const {
      _id,
      article_title,
      main_topic,
      secondary_topics,
      sub_topic,
      articleBody,
      short_summary,
      full_summary,
      clarify_topic,
      produce_deliverables,
      new_ideas,
      include_results,
      permission,
      visibility,

      // 👇 comes from the hidden input in the form when launched via “publish now”
      fromUpcomingId,
    } = req.body;

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // sanitize + word count
    const cleanHtml = sanitizeHtml(articleBody, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'img']),
      allowedAttributes: { '*': ['style', 'href', 'target', 'src', 'alt'] },
    });

    const plainText = cleanHtml.replace(/<[^>]*>/g, ' ').trim();
    const wordCount = plainText.split(/\s+/).filter(Boolean).length;

    if (wordCount < 800 || wordCount > 1200) {
      return res.status(400).render('unit_form_views/form_article', {
        layout: 'unitformlayout',
        data: { ...req.body, article_body: cleanHtml },
        errorMessage: `Your article must be between 800 and 1200 words. Current word count: ${wordCount}.`,
        mainTopics,
      });
    }

    // checkboxes
    const booleanFields = [
      'clarify_topic',
      'produce_deliverables',
      'new_ideas',
      'include_results',
      'permission',
    ];
    const normalizedBooleans = {};
    for (const field of booleanFields) normalizedBooleans[field] = req.body[field] === 'on';

    // secondary topic (single optional)
    const parsedSecondaryTopics =
      secondary_topics && typeof secondary_topics === 'string' && secondary_topics.trim() !== ''
        ? [secondary_topics]
        : [];

    const articleData = {
      article_title,
      main_topic,
      secondary_topics: parsedSecondaryTopics,
      sub_topic,
      article_body: cleanHtml,
      short_summary,
      full_summary,
      visibility,
      author: { id: req.user._id },
      ...normalizedBooleans,
    };

    // image upload (optional)
    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = uploader.upload_stream(
          { folder: 'twennie_articles', resource_type: 'image' },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        const readable = new Readable();
        readable._read = () => {};
        readable.push(req.file.buffer);
        readable.push(null);
        readable.pipe(stream);
      });

      articleData.image = {
        public_id: uploadResult.public_id,
        url: uploadResult.secure_url,
      };
    }

    if (!articleData.image) {
      articleData.image = { public_id: null, url: '/images/default-article.png' };
    }

    // create/update
    let article;
    if (_id) {
      article = await Article.findByIdAndUpdate(_id, articleData, {
        new: true,
        runValidators: true,
      });
      console.log(`Article with ID ${_id} updated successfully.`);
    } else {
      article = new Article(articleData);
      await article.save();
      console.log('New article created successfully.');
    }

    // 🔁 If this came from an upcoming: migrate tags → article, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: article._id,
        toUnitType: 'article',
      });
    }

    // ✅ Always show success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'article',
      unit: article,
      word_count: wordCount,
    });
  } catch (error) {
    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    console.error('Error submitting article:', error);

    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: error.message || 'An error occurred while submitting the article.',
    });
  }
},











    
    

submitVideo: async (req, res) => {
  try {
    // CSRF (keep your existing guard)
    if (process.env.NODE_ENV === 'production' && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // Pull out id + upcoming context, keep the rest as payload
    const { _id, fromUpcomingId, ...videoData } = req.body;

    // Convert checkbox "on" -> true
    const booleanFields = ['clarify_topic', 'produce_deliverables', 'new_ideas', 'engaging', 'permission'];
    booleanFields.forEach((field) => {
      videoData[field] = req.body[field] === 'on';
    });

    // Normalize optional secondary topic (single string -> [string])
    if (typeof videoData.secondary_topics === 'string' && videoData.secondary_topics.trim() !== '') {
      videoData.secondary_topics = [videoData.secondary_topics];
    } else if (!Array.isArray(videoData.secondary_topics)) {
      videoData.secondary_topics = [];
    }

    // Attach author
    videoData.author = { id: req.user._id };

    // Create or update
    let video;
    if (_id) {
      video = await Video.findByIdAndUpdate(_id, videoData, { new: true, runValidators: true });
      console.log(`Video with ID ${_id} updated successfully.`);
    } else {
      video = new Video(videoData);
      await video.save();
      console.log('New video created successfully.');
    }

    // 🔁 If published from an upcoming, migrate tags → video, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: video._id,
        toUnitType: 'video',
      });
    }

    // ✅ Always render success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'video',
      unit: video,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error submitting video:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage: 'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while submitting the video.',
    });
  }
},

    

    



submitInterview: async (req, res) => {
  try {
    // CSRF guard (keep your existing behavior)
    if (!isDevelopment && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // Pull out id + upcoming context; keep the rest as payload
    const { _id, fromUpcomingId, ...interviewData } = req.body;

    // Convert checkbox "on" -> true
    const booleanFields = ['clarify_topic', 'produce_deliverables', 'new_ideas', 'engaging', 'permission'];
    booleanFields.forEach((field) => {
      interviewData[field] = req.body[field] === 'on';
    });

    // Normalize optional secondary topic (single string -> [string])
    if (typeof interviewData.secondary_topics === 'string' && interviewData.secondary_topics.trim() !== '') {
      interviewData.secondary_topics = [interviewData.secondary_topics];
    } else if (!Array.isArray(interviewData.secondary_topics)) {
      interviewData.secondary_topics = [];
    }

    // Attach author
    interviewData.author = { id: req.user._id };

    // Create or update
    let interview;
    if (_id) {
      interview = await Interview.findByIdAndUpdate(_id, interviewData, { new: true, runValidators: true });
      console.log(`Interview with ID ${_id} updated successfully.`);
    } else {
      interview = new Interview(interviewData);
      await interview.save();
      console.log('New interview created successfully.');
    }

    // 🔁 If published from an upcoming, migrate tags → interview, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: interview._id,
        toUnitType: 'interview',
      });
    }

    // ✅ Always render success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'interview',
      unit: interview,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error submitting interview:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage: 'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while submitting the interview.',
    });
  }
},

    
    getPromptForm: async (req, res) => {

        try {
          console.log('New prompt set form requested');
      
          // Load existing data if editing; otherwise, use an empty object
          const existingData = req.promptSet || {};
      
          // Retrieve any selected badge from the session (if a badge was chosen)
          const selectedBadge = req.session.selectedBadge || {};
      
          // Attach the badge to the data (so the form will display it)
          existingData.badge = selectedBadge;
      
          // Clear the badge from the session so that a new blank form won’t pre-fill a badge
          req.session.selectedBadge = null;
      
          res.render('unit_form_views/form_promptset', {
            layout: 'unitformlayout',
            data: existingData, // Pre-filled for editing, empty for new
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
              'AI in Learning'
            ],
            secondaryTopics: [
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
              'AI in Learning'
            ],
            characteristics: [
              'educational',
              'motivational',
              'provocative',
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
              'other'
            ],
            frequencies: ['daily', 'weekly', 'monthly', 'quarterly'],
            csrfToken: isDevelopment ? null : req.csrfToken(),
          });
        } catch (error) {
          console.error('Error loading new prompt set form:', error);
          res.status(500).render('unit_form_views/error', {
            layout: 'unitformlayout',
            title: 'Error',
            errorMessage: 'An error occurred while loading the form.',
          });
        }
      },
      
    
    
    

submitPromptSet: async (req, res) => {
  try {
    // CSRF guard (match your existing pattern)
    if (!isDevelopment && !req.body._csrf) {
      console.error('CSRF validation failed: CSRF token is missing or invalid.');
      throw new Error('CSRF token is missing or invalid.');
    }

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // Pull out id + upcoming context; keep the rest as payload
    const { _id, fromUpcomingId, ...promptSetData } = req.body;
    console.log('Raw request body:', req.body);

    // Checkbox "on" -> true
    const booleanFields = [
      'clarify_topic',
      'topics_and_enlightenment',
      'challenge',
      'instructions',
      'time',
      'permission'
    ];
    booleanFields.forEach((field) => {
      promptSetData[field] = req.body[field] === 'on';
    });
    console.log(
      'Converted boolean fields:',
      booleanFields.reduce((obj, f) => ((obj[f] = promptSetData[f]), obj), {})
    );

    // Optional: normalize a single secondary topic (string -> [string])
    if (typeof promptSetData.secondary_topics === 'string' && promptSetData.secondary_topics.trim() !== '') {
      promptSetData.secondary_topics = [promptSetData.secondary_topics];
    } else if (!Array.isArray(promptSetData.secondary_topics)) {
      promptSetData.secondary_topics = [];
    }

    // Badge flattening -> nested object
    if (promptSetData['badge.image'] || promptSetData['badge.name']) {
      promptSetData.badge = {
        image: promptSetData['badge.image'],
        name: promptSetData['badge.name'],
      };
      delete promptSetData['badge.image'];
      delete promptSetData['badge.name'];
    }

    // Attach author
    promptSetData.author = { id: req.user._id };
    console.log('Author ID set to:', req.user._id);

    // Extract prompts and headlines 1..20
    for (let i = 1; i <= 20; i++) {
      promptSetData[`prompt_headline${i}`] = req.body[`prompt_headline${i}`] || '';
      promptSetData[`Prompt${i}`] = req.body[`Prompt${i}`] || '';
    }

    console.log('Processed prompt set data:', promptSetData);

    // Create or update
    let promptSet;
    if (_id) {
      console.log(`Updating existing prompt set with ID: ${_id}`);
      promptSet = await PromptSet.findByIdAndUpdate(_id, promptSetData, { new: true, runValidators: true });
      if (!promptSet) {
        console.error(`No prompt set found with ID: ${_id}`);
        throw new Error(`Failed to update: No prompt set found with ID ${_id}.`);
      }
      console.log(`Prompt set with ID ${_id} updated successfully.`);
    } else {
      console.log('Creating new prompt set.');
      promptSet = new PromptSet(promptSetData);
      await promptSet.save();
      console.log('New prompt set created successfully.');
    }

    // 🔁 If published from an upcoming: migrate tags → promptset, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: promptSet._id,
        toUnitType: 'promptset',
      });
    }

    // ✅ Always render success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'promptset',
      unit: promptSet,
      csrfToken: isDevelopment ? null : req.csrfToken(),
    });
  } catch (error) {
    console.error('Error submitting prompt set:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage: 'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: error.message || 'An error occurred while submitting the prompt set.',
    });
  }
},

      
      
submitExercise: async (req, res) => {
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
    'Pull Marketing', // ✅ Make sure this is here
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

  try {
    // CSRF guard
    if (!isDevelopment && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // Pull id + upcoming context; keep rest as payload
    const { _id, fromUpcomingId, ...exerciseData } = req.body;

    // Checkbox "on" -> boolean
    const booleanFields = [
      'clarify_topic',
      'topics_and_enlightenment',
      'challenge',
      'instructions',
      'time',
      'permission',
    ];
    booleanFields.forEach((field) => {
      exerciseData[field] = req.body[field] === 'on';
    });

    // Optional: normalize a single secondary topic (string -> [string])
    if (typeof exerciseData.secondary_topics === 'string' && exerciseData.secondary_topics.trim() !== '') {
      exerciseData.secondary_topics = [exerciseData.secondary_topics];
    } else if (!Array.isArray(exerciseData.secondary_topics)) {
      exerciseData.secondary_topics = [];
    }

    // Attach author
    exerciseData.author = { id: req.user._id };

    // Handle document uploads (multer sets req.files)
    if (Array.isArray(req.files) && req.files.length > 0) {
      const uploadPromises = req.files.map((file) => new Promise((resolve, reject) => {
        const baseName = file.originalname.replace(/\.[^/.]+$/, '');
        const stream = uploader.upload_stream(
          {
            folder: 'twennie_exercises',
            resource_type: 'raw',
            public_id: baseName, // keep the original base name
            overwrite: true,
          },
          (error, result) => (error ? reject(error) : resolve(result?.secure_url || null))
        );
        if (file?.buffer) stream.end(file.buffer);
        else resolve(null);
      }));

      const documentUrls = (await Promise.all(uploadPromises)).filter(Boolean);
      // append to existing or set new
      if (Array.isArray(exerciseData.document_uploads) && exerciseData.document_uploads.length) {
        exerciseData.document_uploads = [...exerciseData.document_uploads, ...documentUrls];
      } else {
        exerciseData.document_uploads = documentUrls;
      }
    }

    // Create or update
    let exercise;
    if (_id) {
      exercise = await Exercise.findByIdAndUpdate(_id, exerciseData, {
        new: true,
        runValidators: true,
      });
      if (!exercise) throw new Error(`Exercise not found for ID ${_id}.`);
      console.log(`Exercise with ID ${_id} updated successfully.`);
    } else {
      exercise = new Exercise(exerciseData);
      await exercise.save();
      console.log('New exercise created successfully.');
    }

    // 🔁 If publishing from an upcoming: migrate tags → exercise, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: exercise._id,
        toUnitType: 'exercise',
      });
    }

    // ✅ Always render success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'exercise',
      unit: exercise,
      csrfToken: isDevelopment ? null : req.csrfToken(),
    });

  } catch (error) {
    console.error('Error submitting exercise:', error);

    // Validation error → re-render form with data + topics
    if (error.name === 'ValidationError') {
      return res.status(400).render('unit_form_views/form_exercise', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: error.message,
        mainTopics,
        csrfToken: isDevelopment ? null : req.csrfToken(),
      });
    }

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage: 'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while submitting the exercise.',
    });
  }
},

    
submitTemplate: async (req, res) => {
  try {
    // CSRF guard
    if (!isDevelopment && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    // Pull id + upcoming context; keep rest as payload
    const { _id, fromUpcomingId, ...templateData } = req.body;

    // Checkbox "on" -> boolean
    const booleanFields = [
      'clarify_topic',
      'produce_deliverables',
      'new_ideas',
      'engaging',
      'permission', // ⬅️ removed 'file_format' (not a boolean)
    ];
    booleanFields.forEach((field) => {
      templateData[field] = req.body[field] === 'on';
    });

    // Optional: normalize a single secondary topic (string -> [string])
    if (typeof templateData.secondary_topics === 'string' && templateData.secondary_topics.trim() !== '') {
      templateData.secondary_topics = [templateData.secondary_topics];
    } else if (!Array.isArray(templateData.secondary_topics)) {
      templateData.secondary_topics = [];
    }

    // Attach author
    templateData.author = { id: req.user._id };

    // For new templates, at least one file is required
    if (!_id && (!req.files || req.files.length === 0)) {
      return res.status(400).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Missing File',
        errorMessage: 'Please upload your template document before submitting.',
      });
    }

    // Upload any provided files (append on edit)
    let uploadedFiles = [];
    if (Array.isArray(req.files) && req.files.length > 0) {
      uploadedFiles = await Promise.all(
        req.files.map(
          (file) =>
            new Promise((resolve, reject) => {
              const baseName = file.originalname.replace(/\.[^/.]+$/, '');
              const stream = uploader.upload_stream(
                {
                  resource_type: 'raw',
                  folder: 'twennie_templates',
                  public_id: baseName,
                  overwrite: true,
                },
                (error, result) => {
                  if (error) return reject(new Error('Cloudinary upload failed: ' + error.message));
                  resolve({
                    filename: file.originalname,
                    mimetype: file.mimetype,
                    url: result.secure_url,
                  });
                }
              );

              if (file?.buffer) {
                const readable = new Readable();
                readable._read = () => {};
                readable.push(file.buffer);
                readable.push(null);
                readable.pipe(stream);
              } else {
                resolve(null);
              }
            })
        )
      );
      uploadedFiles = uploadedFiles.filter(Boolean);
    }

    let templateDoc;

    if (_id) {
      // Edit: fetch current to preserve/append existing uploads
      const existing = await Template.findById(_id);
      if (!existing) throw new Error(`Template not found for ID ${_id}.`);

      const mergedUploads =
        uploadedFiles.length > 0
          ? [ ...(existing.documentUploads || []), ...uploadedFiles ]
          : existing.documentUploads || [];

      templateDoc = await Template.findByIdAndUpdate(
        _id,
        { ...templateData, documentUploads: mergedUploads },
        { new: true, runValidators: true }
      );
      console.log(`Template with ID ${_id} updated successfully.`);
    } else {
      // Create: must have at least one upload (guarded above)
      templateData.documentUploads = uploadedFiles;
      templateDoc = new Template(templateData);
      await templateDoc.save();
      console.log('New template created successfully.');
    }

    // 🔁 If publishing from an upcoming: migrate tags → template, then delete upcoming
    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: templateDoc._id,
        toUnitType: 'template',
      });
    }

    // ✅ Always render success page
    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'template',
      unit: templateDoc,
      csrfToken: isDevelopment ? null : req.csrfToken(),
    });
  } catch (error) {
    console.error('Error submitting template:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while submitting the template.',
    });
  }
}

    };
      
      module.exports = unitFormController;
      


