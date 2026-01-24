const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const PromptSet = require('../models/unit_models/promptset');
const Template = require('../models/unit_models/template');
const Exercise = require('../models/unit_models/exercise');

const { uploader } = require('../utils/cloudinary');
const { Readable } = require('stream');
const sanitizeHtml = require('sanitize-html');
const Upcoming = require('../models/unit_models/upcoming'); // ← add this
const Tag = require('../models/tag'); 
console.log('unitFormController loaded');
const Nugget = require('../models/unit_models/nugget');
const Mission = require('../models/unit_models/mission'); // 👈 ADD THIS



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

// ✅ Require Terms acceptance before allowing any content submission/posting
// ✅ Require Terms acceptance before allowing any content submission/posting
function requireTermsForPosting(req, res) {
  if (!req.user || !req.user._id) {
    res.status(401).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Unauthorized',
      errorMessage: 'Please log in to submit content.',
    });
    return false;
  }

  if (req.user.termsAccepted === true) return true;

  // ✅ Correct route: /termsconditions (NOT /terms)
  res.status(403).render('unit_form_views/error', {
    layout: 'unitformlayout',
    title: 'Terms Required',
    errorMessage: 'You must agree to Terms & Conditions before submitting content.',
    ctaLink: '/termsconditions?next=' + encodeURIComponent(req.originalUrl),
    ctaText: 'Review & Accept Terms',
  });

  return false;
}




const createGetFormHandler = (unitType, viewPath, { requireTerms = false } = {}) => (req, res) => {
  console.log(`🛡 Rendering ${unitType} form. CSRF available:`, typeof req.csrfToken === 'function');

  try {
    // Optional: require terms BEFORE the user can even see the form
    if (requireTerms) {
      if (!requireTermsForPosting(req, res)) return;
    }

    const mainTopics = [
      'AI in Consulting',
      'AI in Learning',
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
      'Cross Selling in Multi-Disciplinary Firms',
      'CRM Platforms',
      'Designing a Proposal Process',
      'Emotional Intelligence',
      'Employee Experience',
      'Finding Projects Before they Become RFPs',
      'Integrated Project Delivery or IPD',
      'Leadership in Technical Consulting',
      'Leading Change',
      'Leading Groups on Twennie',
      'Making a Proposal Easy to Read, Skim, and Evaluate',
      'Managing Scope So It Doesnt Manage You',
      'Mental Health in Consulting Environments',
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
      'Team Building in Consulting',
      'The Advantage of Failure',
      'The First 10 Days of a Project',
      'The Pareto Principle',
      'The Power of Play in the Workplace',
      'The Power of Purpose',
      'Tips and Tricks for Proposal Proofreading',
      'Turning a Project into a Business Development Powerhouse',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
      'Using Lean in Project Management',
      'When the Workload is Light',
      'Workplace Culture'
    ];

    return res.render(`unit_form_views/${viewPath}`, {
      layout: 'unitformlayout',
      unitType,
      mainTopics,
      data: {},
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error(`Error rendering form for ${unitType}:`, error);
    return res.status(500).send(`Error rendering form for ${unitType}.`);
  }
};


const unitFormController = {
    // Explicitly created handlers
// Explicitly created handlers (updated: optional terms gate on GET)
getArticleForm: createGetFormHandler('article', 'form_article', { requireTerms: true }),
getVideoForm: createGetFormHandler('video', 'form_video', { requireTerms: true }),
getInterviewForm: createGetFormHandler('interview', 'form_interview', { requireTerms: true }),

getExerciseForm: createGetFormHandler('exercise', 'form_exercise', { requireTerms: true }),
getTemplateForm: createGetFormHandler('template', 'form_template', { requireTerms: true }),

getMissionForm: (req, res) => {
  console.log('🛡 Rendering mission form. CSRF available:', typeof req.csrfToken === 'function');

  try {
    // ✅ Gate form access (not just submission)
    if (!requireTermsForPosting(req, res)) return;

    const mainTopics = [
      'AI in Consulting',
      'AI in Learning',
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
      'Cross Selling in Multi-Disciplinary Firms',
      'CRM Platforms',
      'Designing a Proposal Process',
      'Emotional Intelligence',
      'Employee Experience',
      'Finding Projects Before they Become RFPs',
      'Integrated Project Delivery or IPD',
      'Leadership in Technical Consulting',
      'Leading Change',
      'Leading Groups on Twennie',
      'Making a Proposal Easy to Read, Skim, and Evaluate',
      'Managing Scope So It Doesnt Manage You',
      'Mental Health in Consulting Environments',
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
      'Team Building in Consulting',
      'The Advantage of Failure',
      'The First 10 Days of a Project',
      'The Pareto Principle',
      'The Power of Play in the Workplace',
      'The Power of Purpose',
      'Tips and Tricks for Proposal Proofreading',
      'Turning a Project into a Business Development Powerhouse',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
      'Using Lean in Project Management',
      'When the Workload is Light',
      'Workplace Culture'
    ];

    const fromUpcomingId = req.query.fromUpcomingId || '';

    return res.render('unit_form_views/form_mission', {
      layout: 'unitformlayout',
      unitType: 'mission',
      data: {},
      mainTopics,
      fromUpcomingId,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error rendering mission form:', error);
    return res.status(500).send('Error rendering form for mission.');
  }
},


getNuggetForm: (req, res) => {
  try {
    // ✅ Gate form access (not just submission)
    if (!requireTermsForPosting(req, res)) return;

    return res.render('unit_form_views/form_nugget', {
      layout: 'unitformlayout',
      unitType: 'nugget',
      data: {},
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error rendering nugget form:', error);
    return res.status(500).send('Error rendering nugget form.');
  }
},

    // POST Handlers with Validation
// POST Handlers with Validation (rewritten: consistent auth + terms gate + csrf helper)
submitUnit: (Model, unitType, validateFunction) => async (req, res) => {
  try {
    console.log(`Received POST request for ${unitType}:`, req.body);

    // ✅ Auth + terms gate (consistent with other submit handlers)
    if (!requireTermsForPosting(req, res)) return;

    // ✅ Validate body
    const errors = validateFunction(req.body);
    if (errors.length > 0) {
      return res.render(`unit_form_views/form_${unitType}`, {
        layout: 'unitformlayout',
        data: req.body,
        errors,
        csrfToken: getCsrfToken(req),
      });
    }

    // ✅ Build payload (prefer explicit author.id from req.user)
    const unitData = {
      author: { id: req.user._id },
      topic: req.body.topic || 'No topic specified',
      ...req.body,
    };

    // ✅ Create or update
    const unit = req.body._id
      ? await Model.findByIdAndUpdate(req.body._id, unitData, {
          new: true,
          runValidators: true,
        })
      : await Model.create(unitData);

    console.log(`Saved ${unitType} successfully:`, unit);

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType,
      unit,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error(`${unitType} submission error:`, error);

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
      errorMessage: 'An error occurred while submitting the unit.',
    });
  }
},

    

    // Success Page Handler
// Success Page Handler (rewritten: consistent csrf + safe model lookup)
showSuccessPage: async (req, res) => {
  const { unitType, id, error } = req.query;

  try {
    let unit = null;

    if (id && unitType) {
      const Model = {
        article: Article,
        video: Video,
        interview: Interview,
        promptset: PromptSet,
        template: Template,
        exercise: Exercise,
        nugget: Nugget,
        mission: Mission,
        upcoming: Upcoming,
      }[unitType];

      if (!Model) {
        console.warn(`[showSuccessPage] Unknown unitType: ${unitType}`);
      } else {
        unit = await Model.findById(id);
        console.log(`[showSuccessPage] Fetched ${unitType} for success page:`, unit?._id || unit);
      }
    }

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType,
      unit,
      error,
      csrfToken: getCsrfToken(req),
    });
  } catch (fetchError) {
    console.error(`[showSuccessPage] Error fetching ${unitType} details:`, fetchError);

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'Unable to fetch unit details.',
      csrfToken: getCsrfToken(req),
    });
  }
},



// ↓ add alongside your explicit "getXForm" handlers
getUpcomingForm: (req, res) => {
  console.log('🛡 Rendering upcoming form. CSRF available:', typeof req.csrfToken === 'function');

  try {
    // ✅ Gate form access (not just submission)
    if (!requireTermsForPosting(req, res)) return;

    const mainTopics = [
      'AI in Consulting',
      'AI in Learning',
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
      'Cross Selling in Multi-Disciplinary Firms',
      'CRM Platforms',
      'Designing a Proposal Process',
      'Emotional Intelligence',
      'Employee Experience',
      'Finding Projects Before they Become RFPs',
      'Integrated Project Delivery or IPD',
      'Leadership in Technical Consulting',
      'Leading Change',
      'Leading Groups on Twennie',
      'Making a Proposal Easy to Read, Skim, and Evaluate',
      'Managing Scope So It Doesnt Manage You',
      'Mental Health in Consulting Environments',
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
      'Team Building in Consulting',
      'The Advantage of Failure',
      'The First 10 Days of a Project',
      'The Pareto Principle',
      'The Power of Play in the Workplace',
      'The Power of Purpose',
      'Tips and Tricks for Proposal Proofreading',
      'Turning a Project into a Business Development Powerhouse',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
      'Using Lean in Project Management',
      'When the Workload is Light',
      'Workplace Culture'
    ];

    const unitTypes = [
      'article','video','interview','exercise','template',
      'promptset','nugget','mission'
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
// ---- submitUpcoming (rewritten for consistency: req.user only) ----
submitUpcoming: async (req, res) => {
  try {
    const mainTopics = [
      'AI in Consulting',
      'AI in Learning',
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
      'Cross Selling in Multi-Disciplinary Firms',
      'CRM Platforms',
      'Designing a Proposal Process',
      'Emotional Intelligence',
      'Employee Experience',
      'Finding Projects Before they Become RFPs',
      'Integrated Project Delivery or IPD',
      'Leadership in Technical Consulting',
      'Leading Change',
      'Leading Groups on Twennie',
      'Making a Proposal Easy to Read, Skim, and Evaluate',
      'Managing Scope So It Doesnt Manage You',
      'Mental Health in Consulting Environments',
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
      'Team Building in Consulting',
      'The Advantage of Failure',
      'The First 10 Days of a Project',
      'The Pareto Principle',
      'The Power of Play in the Workplace',
      'The Power of Purpose',
      'Tips and Tricks for Proposal Proofreading',
      'Turning a Project into a Business Development Powerhouse',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
      'Using Lean in Project Management',
      'When the Workload is Light',
      'Workplace Culture'
    ];

    const unitTypes = [
      'article','video','interview','exercise','template',
      'promptset','nugget','mission'
    ];

    // ✅ Auth + terms gate (single source of truth)
    if (!requireTermsForPosting(req, res)) return;

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
        unitTypes,
        csrfToken: getCsrfToken(req),
      });
    }

    // Normalize optional secondary topics into array
    const parsedSecondaryTopics =
      Array.isArray(secondary_topics)
        ? secondary_topics.filter(Boolean)
        : (typeof secondary_topics === 'string' && secondary_topics.trim() !== '')
          ? [secondary_topics.trim()]
          : [];

    const ALLOWED_STATUS = ['in production', 'released', 'cancelled'];
    const safeStatus = ALLOWED_STATUS.includes(status) ? status : 'in production';

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

    // Optional image upload
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

    // Default image (create mode only)
    if (!payload.image && !_id) {
      payload.image = { public_id: null, url: '/images/default-upcoming.png' };
    }

    let upcoming;

    if (_id) {
      upcoming = await Upcoming.findByIdAndUpdate(_id, payload, {
        new: true,
        runValidators: true,
      });

      if (!upcoming) {
        return res.status(404).render('unit_form_views/error', {
          layout: 'unitformlayout',
          title: 'Not Found',
          errorMessage: 'Upcoming unit not found for editing.',
          csrfToken: getCsrfToken(req),
        });
      }

      // Backfill creator only if missing
      if (!upcoming.createdBy) {
        upcoming.createdBy = req.user._id;
        if (req.user.membershipType) upcoming.createdByModel = req.user.membershipType;
        await upcoming.save();
      }

      console.log(`Upcoming with ID ${_id} updated successfully.`);
    } else {
      payload.createdBy = req.user._id;
      if (req.user.membershipType) payload.createdByModel = req.user.membershipType;

      upcoming = new Upcoming(payload);
      await upcoming.save();
      console.log('New upcoming unit created successfully.');
    }

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
        errorMessage: 'Upcoming unit not found.',
        csrfToken: getCsrfToken(req),
      });
    }

    const mainTopics = [
      'AI in Consulting',
      'AI in Learning',
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
      'Cross Selling in Multi-Disciplinary Firms',
      'CRM Platforms',
      'Designing a Proposal Process',
      'Emotional Intelligence',
      'Employee Experience',
      'Finding Projects Before they Become RFPs',
      'Integrated Project Delivery or IPD',
      'Leadership in Technical Consulting',
      'Leading Change',
      'Leading Groups on Twennie',
      'Making a Proposal Easy to Read, Skim, and Evaluate',
      'Managing Scope So It Doesnt Manage You',
      'Mental Health in Consulting Environments',
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
      'Team Building in Consulting',
      'The Advantage of Failure',
      'The First 10 Days of a Project',
      'The Pareto Principle',
      'The Power of Play in the Workplace',
      'The Power of Purpose',
      'Tips and Tricks for Proposal Proofreading',
      'Turning a Project into a Business Development Powerhouse',
      'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
      'Using Lean in Project Management',
      'When the Workload is Light',
      'Workplace Culture'
    ];

    // Image fallback
    const image = upcoming.image?.url
      ? upcoming.image
      : { public_id: null, url: '/images/default-upcoming.png' };

    const fromUpcomingId = upcoming._id.toString();

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
        fromUpcomingId,
        csrfToken: getCsrfToken(req),
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
        fromUpcomingId,
        csrfToken: getCsrfToken(req),
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
        fromUpcomingId,
        csrfToken: getCsrfToken(req),
      });
    }

    return res.status(400).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Unsupported',
      errorMessage: `Prefill for unit type "${unitType}" is not configured yet.`,
      csrfToken: getCsrfToken(req),
    });

  } catch (err) {
    console.error('prefillFromUpcoming error:', err);

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'Could not prefill from upcoming.',
      csrfToken: getCsrfToken(req),
    });
  }
},



submitNugget: async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;

    const {
      _id,
      title,
      client,
      horizon,
      discipline,
      region,
      'estimatedValue.amount': estimatedValueAmount,
      projectDeliveryType,
      'originalSource.label': sourceLabel,
      'originalSource.url': sourceUrl,
      likelihood,
      connectedTwennieUnits,
      notes,
      visibility,
      fromUpcomingId
    } = req.body;

    const errors = [];
    if (!title?.trim()) errors.push('Title is required.');
    if (!client?.trim()) errors.push('Client is required.');
    if (!horizon) errors.push('Horizon is required.');
    if (!sourceLabel?.trim()) errors.push('Original source label is required.');

    if (errors.length) {
      return res.status(400).render('unit_form_views/form_nugget', {
        layout: 'unitformlayout',
        unitType: 'nugget',
        data: req.body,
        errors,
        csrfToken: getCsrfToken(req),
      });
    }

    // normalize connected units (textarea → array or objects)
    let parsedConnected = [];
    if (connectedTwennieUnits) {
      try {
        parsedConnected = JSON.parse(connectedTwennieUnits);
      } catch {
        parsedConnected = connectedTwennieUnits
          .split(',')
          .map(s => ({ kind: 'article', unitId: s.trim() }))
          .filter(x => x.unitId);
      }
    }

    const nuggetData = {
      title: title.trim(),
      client: client.trim(),
      horizon,
      discipline: discipline?.trim(),
      region: region?.trim(),
      estimatedValue: {
        amount: estimatedValueAmount ? Number(estimatedValueAmount) : undefined,
        currency: 'CAD'
      },
      projectDeliveryType: projectDeliveryType || 'unknown',
      originalSource: {
        label: sourceLabel.trim(),
        url: sourceUrl?.trim()
      },
      likelihood: likelihood ? Number(likelihood) : 50,
      connectedTwennieUnits: parsedConnected,
      notes: notes?.trim(),
      visibility: visibility || 'team_only',
      createdBy: req.user._id
    };

    let nugget;
    if (_id) {
      nugget = await Nugget.findByIdAndUpdate(_id, nuggetData, {
        new: true,
        runValidators: true
      });
      console.log(`Nugget with ID ${_id} updated successfully.`);
    } else {
      nugget = new Nugget(nuggetData);
      await nugget.save();
      console.log('New nugget created successfully.');
    }

    if (fromUpcomingId) {
      await migrateAndDeleteUpcoming({
        fromUpcomingId,
        toItemId: nugget._id,
        toUnitType: 'nugget',
      });
    }

    // Make success template happy (it checks for *_title fields)
    const unitForSuccess = {
      ...nugget.toObject(),
      nugget_title: nugget.title
    };

    const viewLink = `/unitviews/nuggets/view/${nugget._id}`;
    const createLink = `/unitform/form_nugget`;

    // ✅ Use real dashboard routes (no /dashboard)
    const dashboardLink =
      req.user?.membershipType === 'leader' ? '/dashboard/leader' :
      req.user?.membershipType === 'group_member' ? '/dashboard/groupmember' :
      '/dashboard/member';

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'nugget',
      unit: unitForSuccess,
      viewLink,
      createLink,
      dashboardLink,
      csrfToken: getCsrfToken(req),
    });

  } catch (error) {
    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    console.error('Error submitting nugget:', error);

    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage: 'Your session has expired. Please refresh and try again.',
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: error.message || 'An error occurred while submitting the nugget.',
    });
  }
},





submitArticle: async (req, res) => {
  try {
    const mainTopics = [
  'AI in Consulting',
  'AI in Learning',
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
  'Cross Selling in Multi-Disciplinary Firms',
  'CRM Platforms',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
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
  'Team Building in Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
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

    if (!requireTermsForPosting(req, res)) return;


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
    csrfToken: getCsrfToken(req),
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

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;


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

    // Helper: determine published state robustly
    const isPublished = (() => {
      const status =
        (typeof video.status !== 'undefined' ? video.status : undefined) ??
        videoData.status ??
        videoData.publish_status ??
        video.is_published ??
        videoData.is_published;

      // Accept common patterns: boolean true or status string "published"
      return status === true || String(status).toLowerCase() === 'published';
    })();

    /**
     * If this video came from an Upcoming item AND it's now published:
     * - migrate any tags/links from the upcoming → this video
     * - delete the upcoming record
     *
     * NOTE: We only touch Upcoming when we have explicit context (fromUpcomingId)
     * and the item is published. Drafts/updates without publishing do nothing here.
     */
    if (fromUpcomingId && isPublished) {
      try {
        await migrateAndDeleteUpcoming({
          fromUpcomingId,
          toItemId: video._id,
          toUnitType: 'video',
        });
        console.log(`Upcoming ${fromUpcomingId} migrated and deleted after publish.`);
      } catch (migrateErr) {
        console.error('Failed migrating/deleting upcoming during publish:', migrateErr);
        // Non-fatal: proceed to success page; the unit is saved.
      }
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

    if (!requireTermsForPosting(req, res)) return;


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

    // Determine "published" state robustly
    const isPublished = (() => {
      const status =
        (typeof interview.status !== 'undefined' ? interview.status : undefined) ??
        interviewData.status ??
        interviewData.publish_status ??
        interview.is_published ??
        interviewData.is_published;

      return status === true || String(status).toLowerCase() === 'published';
    })();

    /**
     * If this interview came from an Upcoming item AND it's now published:
     * - migrate any tags/links from the upcoming → this interview
     * - delete the upcoming record
     *
     * Draft saves/updates without publishing: do nothing to Upcoming.
     */
    if (fromUpcomingId && isPublished) {
      try {
        await migrateAndDeleteUpcoming({
          fromUpcomingId,
          toItemId: interview._id,
          toUnitType: 'interview',
        });
        console.log(`Upcoming ${fromUpcomingId} migrated and deleted after publish.`);
      } catch (migrateErr) {
        console.error('Failed migrating/deleting upcoming during publish:', migrateErr);
        // Non-fatal; the interview itself is saved.
      }
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

    // ✅ Gate form access (not just submission)
    if (!requireTermsForPosting(req, res)) return;

    // Load existing data if editing; otherwise, use an empty object
    const existingData = req.promptSet || {};

    // Retrieve any selected badge from the session (if a badge was chosen)
    const selectedBadge = req.session.selectedBadge || {};

    // Attach the badge to the data (so the form will display it)
    existingData.badge = selectedBadge;

    // Clear the badge from the session so that a new blank form won’t pre-fill a badge
    req.session.selectedBadge = null;

    return res.render('unit_form_views/form_promptset', {
      layout: 'unitformlayout',
      data: existingData,
      mainTopics: [
        'AI in Consulting','AI in Learning','AI in Project Management','Analytics in Project Management',
        'Business Development in Technical Services','Business Development Metrics','Candid Communication',
        'Career Development in Technical Services','Client Experience','Client Feedback Software',
        'Client Interactions','Closing a Project Strategically','Conducting Color Reviews of Proposals',
        'Cross Selling in Multi-Disciplinary Firms','CRM Platforms','Designing a Proposal Process',
        'Emotional Intelligence','Employee Experience','Finding Projects Before they Become RFPs',
        'Integrated Project Delivery or IPD','Leadership in Technical Consulting','Leading Change',
        'Leading Groups on Twennie','Making a Proposal Easy to Read, Skim, and Evaluate',
        'Managing Scope So It Doesnt Manage You','Mental Health in Consulting Environments',
        'Non-Technical Roles in Technical Environments','People Before Profit','Program Management',
        'Project Management','Project Management Software','Proposal Management','Proposal Strategy',
        'Pull Marketing','Pursuing the Right Projects for Your Firm and Your Team','Remote and Hybrid Work',
        'Rescuing a Project That Has Gone Off the Rails','Risk Management','Social Entrepreneurship',
        'Social Media, Advertising, and Other Mysteries','Soft Skills in Technical Environments',
        'Storytelling in Technical Marketing','Team Building in Consulting','The Advantage of Failure',
        'The First 10 Days of a Project','The Pareto Principle','The Power of Play in the Workplace',
        'The Power of Purpose','Tips and Tricks for Proposal Proofreading',
        'Turning a Project into a Business Development Powerhouse',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Using Lean in Project Management','When the Workload is Light','Workplace Culture'
      ],
      secondaryTopics: [
        'AI in Consulting','AI in Learning','AI in Project Management','Analytics in Project Management',
        'Business Development in Technical Services','Business Development Metrics','Candid Communication',
        'Career Development in Technical Services','Client Experience','Client Feedback Software',
        'Client Interactions','Closing a Project Strategically','Conducting Color Reviews of Proposals',
        'Cross Selling in Multi-Disciplinary Firms','CRM Platforms','Designing a Proposal Process',
        'Emotional Intelligence','Employee Experience','Finding Projects Before they Become RFPs',
        'Integrated Project Delivery or IPD','Leadership in Technical Consulting','Leading Change',
        'Leading Groups on Twennie','Making a Proposal Easy to Read, Skim, and Evaluate',
        'Managing Scope So It Doesnt Manage You','Mental Health in Consulting Environments',
        'Non-Technical Roles in Technical Environments','People Before Profit','Program Management',
        'Project Management','Project Management Software','Proposal Management','Proposal Strategy',
        'Pull Marketing','Pursuing the Right Projects for Your Firm and Your Team','Remote and Hybrid Work',
        'Rescuing a Project That Has Gone Off the Rails','Risk Management','Social Entrepreneurship',
        'Social Media, Advertising, and Other Mysteries','Soft Skills in Technical Environments',
        'Storytelling in Technical Marketing','Team Building in Consulting','The Advantage of Failure',
        'The First 10 Days of a Project','The Pareto Principle','The Power of Play in the Workplace',
        'The Power of Purpose','Tips and Tricks for Proposal Proofreading',
        'Turning a Project into a Business Development Powerhouse',
        'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
        'Using Lean in Project Management','When the Workload is Light','Workplace Culture'
      ],
      characteristics: [
        'educational','motivational','provocative','fun','hilarious','silly','competitive','restorative',
        'energizing','relationship-building','team building','stress-relieving','insightful','calming',
        'reassuring','encouraging','creative','imaginative','heart-warming','other'
      ],
      frequencies: ['daily', 'weekly', 'monthly', 'quarterly'],
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error loading new prompt set form:', error);
    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: 'An error occurred while loading the form.',
      csrfToken: getCsrfToken(req),
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

    if (!requireTermsForPosting(req, res)) return;


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

    // Determine "published" state robustly
    const isPublished = (() => {
      const status =
        (typeof promptSet.status !== 'undefined' ? promptSet.status : undefined) ??
        promptSetData.status ??
        promptSetData.publish_status ??
        promptSet.is_published ??
        promptSetData.is_published;

      // Accept common patterns: boolean true or status string "published"
      return status === true || String(status).toLowerCase() === 'published';
    })();

    /**
     * If this prompt set originated from an Upcoming item AND it's now published:
     * - migrate tags/links from Upcoming → this prompt set
     * - delete the Upcoming record
     *
     * Draft saves/updates without publishing do NOT touch Upcoming.
     */
    if (fromUpcomingId && isPublished) {
      try {
        await migrateAndDeleteUpcoming({
          fromUpcomingId,
          toItemId: promptSet._id,
          toUnitType: 'promptset',
        });
        console.log(`Upcoming ${fromUpcomingId} migrated and deleted after publish.`);
      } catch (migrateErr) {
        console.error('Failed migrating/deleting upcoming during publish:', migrateErr);
        // Non-fatal: proceed to success; the prompt set itself is persisted.
      }
    }

    // ✅ Always render success page
return res.render('unit_form_views/unit_success', {
  layout: 'unitformlayout',
  unitType: 'promptset',
  unit: promptSet,
  csrfToken: getCsrfToken(req),
});
  } catch (error) {
    console.error('Error submitting prompt set:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
return res.status(403).render('unit_form_views/error', {
  layout: 'unitformlayout',
  title: 'Session Expired',
  errorMessage: 'Your session has expired or the form took too long to submit. Please refresh and try again.',
  csrfToken: getCsrfToken(req),
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
  'AI in Consulting',
  'AI in Learning',
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
  'Cross Selling in Multi-Disciplinary Firms',
  'CRM Platforms',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
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
  'Team Building in Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
  ];

  try {
    // CSRF guard
    if (!isDevelopment && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;


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

    // Determine "published" state robustly
    const isPublished = (() => {
      const status =
        (typeof exercise.status !== 'undefined' ? exercise.status : undefined) ??
        exerciseData.status ??
        exerciseData.publish_status ??
        exercise.is_published ??
        exerciseData.is_published;

      // Accept common patterns: boolean true or status string "published"
      return status === true || String(status).toLowerCase() === 'published';
    })();

    // 🔁 Only if this came from an Upcoming AND it's now published → migrate & delete Upcoming
    if (fromUpcomingId && isPublished) {
      try {
        await migrateAndDeleteUpcoming({
          fromUpcomingId,
          toItemId: exercise._id,
          toUnitType: 'exercise',
        });
        console.log(`Upcoming ${fromUpcomingId} migrated and deleted after publish.`);
      } catch (migrateErr) {
        console.error('Failed migrating/deleting upcoming during publish:', migrateErr);
        // Non-fatal: continue; exercise itself is saved.
      }
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
  csrfToken: getCsrfToken(req),
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

    if (!requireTermsForPosting(req, res)) return;


    // Pull id + upcoming context; keep rest as payload
    const { _id, fromUpcomingId, ...templateData } = req.body;

    // Checkbox "on" -> boolean
    const booleanFields = [
      'clarify_topic',
      'produce_deliverables',
      'new_ideas',
      'engaging',
      'permission', // ⬅️ 'file_format' intentionally excluded
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

    // Determine "published" state robustly
    const isPublished = (() => {
      const status =
        (typeof templateDoc.status !== 'undefined' ? templateDoc.status : undefined) ??
        templateData.status ??
        templateData.publish_status ??
        templateDoc.is_published ??
        templateData.is_published;

      // Accept common patterns: boolean true or status string "published"
      return status === true || String(status).toLowerCase() === 'published';
    })();

    // 🔁 Only migrate/delete Upcoming if originated from Upcoming AND is now published
    if (fromUpcomingId && isPublished) {
      try {
        await migrateAndDeleteUpcoming({
          fromUpcomingId,
          toItemId: templateDoc._id,
          toUnitType: 'template',
        });
        console.log(`Upcoming ${fromUpcomingId} migrated and deleted after publish.`);
      } catch (migrateErr) {
        console.error('Failed migrating/deleting upcoming during publish:', migrateErr);
        // Non-fatal: continue; template itself is saved.
      }
    }

    // ✅ Always render success page
return res.render('unit_form_views/unit_success', {
  layout: 'unitformlayout',
  unitType: 'template',
  unit: templateDoc,
  csrfToken: getCsrfToken(req),
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
},

  submitMission: async (req, res) => {
  const mainTopics = [
  'AI in Consulting',
  'AI in Learning',
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
  'Cross Selling in Multi-Disciplinary Firms',
  'CRM Platforms',
  'Designing a Proposal Process',
  'Emotional Intelligence',
  'Employee Experience',
  'Finding Projects Before they Become RFPs',
  'Integrated Project Delivery or IPD',
  'Leadership in Technical Consulting',
  'Leading Change',
  'Leading Groups on Twennie',
  'Making a Proposal Easy to Read, Skim, and Evaluate',
  'Managing Scope So It Doesnt Manage You',
  'Mental Health in Consulting Environments',
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
  'Team Building in Consulting',
  'The Advantage of Failure',
  'The First 10 Days of a Project',
  'The Pareto Principle',
  'The Power of Play in the Workplace',
  'The Power of Purpose',
  'Tips and Tricks for Proposal Proofreading',
  'Turning a Project into a Business Development Powerhouse',
  'Un-Commoditizing Your Services by Delivering What Clients Truly Value',
  'Using Lean in Project Management',
  'When the Workload is Light',
  'Workplace Culture'
  ];

  try {
    // CSRF guard (match your existing pattern)
    if (!isDevelopment && !req.body._csrf) {
      throw new Error('CSRF token is missing or invalid.');
    }

    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;


    const isEdit = !!req.body._id;
    const userId = req.user._id;
    const { fromUpcomingId } = req.body; // present in the form, not used yet

    const {
      mission_title,
      badge_name,
      status,
      visibility,
      main_topic,
      category,
      purpose,
      why_it_matters,
      background,
      department_requesting,
      open_to,
      timeframe,
      estimated_effort_hours,
      job_number,
      budget_amount,
      due_date,
    } = req.body;

    // --- Twennie learning units from hidden inputs (autocomplete chips) ---

    
    let rawTwennieUnits = req.body.twennie_units || [];

    // ensure it's always an array
    if (!Array.isArray(rawTwennieUnits)) {
      rawTwennieUnits = [rawTwennieUnits];
    }

    const twennie_learning_units = rawTwennieUnits
      .filter(v => v && v.trim() !== '')
      .map(v => {
        // v looks like "video:65f1..." or "article:6789..."
        const [unit_type, unit_id] = v.split(':');
        return { unit_type, unit_id };
      })
      .slice(0, 6); // hard cap at 6

    // Basic validations

const errors = [];
if (!mission_title?.trim()) errors.push('Mission title is required.');
if (!badge_name?.trim()) errors.push('Mission badge name is required.');
if (!purpose?.trim()) errors.push('Mission purpose is required.');
if (!why_it_matters?.trim()) errors.push('Please explain why this mission matters.');


    if (errors.length) {
      return res.status(400).render('unit_form_views/form_mission', {
        layout: 'unitformlayout',
        unitType: 'mission',
        data: req.body,
        errors,
        mainTopics,
        csrfToken: getCsrfToken(req),
      });
    }

    // ---- approvals_required ----
    let approvalsRequired = [];
    if (req.body.approvals_required) {
      const rawApprovals = Array.isArray(req.body.approvals_required)
        ? req.body.approvals_required
        : Object.values(req.body.approvals_required);

      approvalsRequired = rawApprovals
        .map((a) => ({
          role: (a.role || '').trim(),
          name: (a.name || '').trim(),
          email: (a.email || '').trim(),
        }))
        .filter((a) => a.role || a.name || a.email);
    }

    // ---- task_instructions ----
    let taskInstructions = [];
    if (req.body.task_instructions) {
      const rawTasks = Array.isArray(req.body.task_instructions)
        ? req.body.task_instructions
        : Object.values(req.body.task_instructions);

      taskInstructions = rawTasks
        .map((t) => {
          const heading = (t.heading || '').trim();
          const instructionsText = t.instructions || '';
          const instructionsArray = instructionsText
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean);

          return {
            heading,
            instructions: instructionsArray,
          };
        })
        .filter((t) => t.heading || t.instructions.length);
    }

    // ---- contacts ----
    let contacts = [];
    if (req.body.contacts) {
      const rawContacts = Array.isArray(req.body.contacts)
        ? req.body.contacts
        : Object.values(req.body.contacts);

      contacts = rawContacts
        .map((c) => ({
          role: (c.role || '').trim(),
          name: (c.name || '').trim(),
          email: (c.email || '').trim(),
          phone: (c.phone || '').trim(),
        }))
        .filter((c) => c.role || c.name || c.email || c.phone);
    }

    // ---- deliverables_checklist ----
    let deliverablesChecklist = [];
    if (req.body.deliverables_checklist) {
      deliverablesChecklist = req.body.deliverables_checklist
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
    }

    const baseData = {
      mission_title: (mission_title || '').trim(),
        badge_name: (badge_name || '').trim(), // ✅ NEW

      // status enum in schema: 'one time mission', 'on-going', 'intermittent'
      status: status || 'one time mission',

      visibility: visibility || 'organization_only',
      main_topic: main_topic || 'When the Workload is Light',
      category: category || 'internal_improvement',

      purpose: (purpose || '').trim(),
      why_it_matters: (why_it_matters || '').trim(),
      background: (background || '').trim(),

      // summaries for mission cards
      short_purpose: (req.body.short_purpose || '').trim(),
      full_summary: (req.body.full_summary || '').trim(),

      department_requesting: (department_requesting || '').trim(),
      open_to: (open_to || '').trim(),
      timeframe: (timeframe || '').trim(),

      estimated_effort_hours: estimated_effort_hours
        ? Number(estimated_effort_hours)
        : undefined,

      job_number: (job_number || '').trim(),
      budget_amount: (budget_amount || '').trim(),

      approvals_required: approvalsRequired,
      task_instructions: taskInstructions,
      contacts,
      deliverables_checklist: deliverablesChecklist,

      due_date: due_date ? new Date(due_date) : undefined,

      // ✅ NEW: linked Twennie units
      twennie_learning_units,
    };

    let mission;

    if (isEdit) {
      mission = await Mission.findById(req.body._id);
      if (!mission) {
        return res.status(404).render('unit_form_views/error', {
          layout: 'unitformlayout',
          title: 'Mission Not Found',
          errorMessage: 'The mission you tried to edit could not be found.',
        });
      }

      Object.assign(mission, baseData);
    } else {
      mission = new Mission({
        ...baseData,
        created_by: userId,
      });
    }

    await mission.save();

    // (Optional later) if you want: migrateAndDeleteUpcoming({ fromUpcomingId, toItemId: mission._id, toUnitType: 'mission' });

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'mission',
      unit: mission,
      csrfToken: getCsrfToken(req),
    });
  } catch (error) {
    console.error('Error submitting mission:', error);

    const isCsrfError = error.code === 'EBADCSRFTOKEN';
    if (isCsrfError) {
      return res.status(403).render('unit_form_views/error', {
        layout: 'unitformlayout',
        title: 'Session Expired',
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
      });
    }

    if (error.name === 'ValidationError') {
      return res.status(400).render('unit_form_views/form_mission', {
        layout: 'unitformlayout',
        unitType: 'mission',
        data: req.body,
        errorMessage: error.message,
        mainTopics,
        csrfToken: getCsrfToken(req),
      });
    }

    return res.status(500).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Error',
      errorMessage: error.message || 'An error occurred while submitting the mission.',
    });
  }
}




    };
      
      module.exports = unitFormController;
      


