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
const topics = require('../config/topics');

function dashboardHomeForUser(user) {
  const type = user?.membershipType || user?.accessLevel;

  if (type === 'leader') return '/dashboard/leader';
  if (type === 'group_member') return '/dashboard/group-member';
  return '/dashboard/member';
}



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
  const userId = req.user?._id || req.user?.id;

  if (!req.user || !userId) {
    res.status(401).render('unit_form_views/error', {
      layout: 'unitformlayout',
      title: 'Unauthorized',
      errorMessage: 'Please log in to submit content.',
    });
    return false;
  }

  if (req.user.termsAccepted === true) return true;

  res.status(403).render('unit_form_views/error', {
    layout: 'unitformlayout',
    title: 'Terms Required',
    errorMessage: 'You must agree to Terms & Conditions before submitting content.',
    ctaLink: '/termsconditions?next=' + encodeURIComponent(req.originalUrl),
    ctaText: 'Review & Accept Terms',
  });

  return false;
}

async function validatePdfUpload(file) {
  if (!file?.buffer) {
    throw new Error('No file uploaded.');
  }

  const mimetype = String(file.mimetype || '').toLowerCase();
  const originalname = String(file.originalname || '').toLowerCase();

  if (mimetype !== 'application/pdf' || !originalname.endsWith('.pdf')) {
    throw new Error('Only PDF files are allowed.');
  }

  const { fileTypeFromBuffer } = await import('file-type');
  const detectedType = await fileTypeFromBuffer(file.buffer);

  if (!detectedType || detectedType.mime !== 'application/pdf') {
    throw new Error('The uploaded file is not a valid PDF.');
  }

  return true;
}



const createGetFormHandler = (unitType, viewPath, { requireTerms = false } = {}) => (req, res) => {
  console.log(`🛡 Rendering ${unitType} form. CSRF available:`, typeof req.csrfToken === 'function');

  try {
    // Optional: require terms BEFORE the user can even see the form
    if (requireTerms) {
      if (!requireTermsForPosting(req, res)) return;
    }

const mainTopics = require('../config/topics');

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

const mainTopics = require('../config/topics');

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
    return res.status(500).send('Error rendering the nugget form.');
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
const userId = req.user?._id || req.user?.id;

const unitData = {
  author: { id: userId },
  main_topic: req.body.main_topic || req.body.topic || 'No topic specified',
  ...req.body,
};

// optional: if topic exists but you don’t want it persisted:
delete unitData.topic;


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

const mainTopics = require('../config/topics');

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
const mainTopics = require('../config/topics');

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
let parsedSecondaryTopics = [];

if (Array.isArray(secondary_topics)) {
  parsedSecondaryTopics = secondary_topics.filter(
    topic => typeof topic === 'string' && topic.trim() !== ''
  );
} else if (typeof secondary_topics === 'string' && secondary_topics.trim() !== '') {
  parsedSecondaryTopics = [secondary_topics.trim()];
}

console.log('req.body.secondary_topics raw:', req.body.secondary_topics);
console.log('Array.isArray(req.body.secondary_topics):', Array.isArray(req.body.secondary_topics));
console.log('typeof req.body.secondary_topics:', typeof req.body.secondary_topics);
console.log('parsedSecondaryTopics:', parsedSecondaryTopics);
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

const mainTopics = require('../config/topics');

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
  'other'
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
          dashboardLink: dashboardHomeForUser(req.user),
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

    const allowedKinds = ['article', 'video', 'interview', 'promptset', 'exercise', 'template'];

    let parsedConnected = [];

    if (connectedTwennieUnits) {
      try {
        const raw = typeof connectedTwennieUnits === 'string'
          ? JSON.parse(connectedTwennieUnits)
          : connectedTwennieUnits;

        if (Array.isArray(raw)) {
          parsedConnected = raw
            .map(unit => {
              if (!unit || typeof unit !== 'object') return null;

              return {
                kind: typeof unit.kind === 'string' ? unit.kind.trim() : '',
                unitId: typeof unit.unitId === 'string' ? unit.unitId.trim() : String(unit.unitId || '').trim(),
                note: typeof unit.note === 'string' ? unit.note.trim() : undefined
              };
            })
            .filter(unit => unit && unit.kind && unit.unitId);
        }
      } catch (err) {
        errors.push('There was a problem reading the selected Twennie learning units.');
      }
    }

    if (parsedConnected.length > 6) {
      errors.push('You can attach up to 6 Twennie learning units.');
    }

    const invalidKinds = parsedConnected.filter(unit => !allowedKinds.includes(unit.kind));
    if (invalidKinds.length) {
      errors.push('One or more selected learning units has an invalid unit type.');
    }

    if (errors.length) {
      return res.status(400).render('unit_form_views/form_nugget', {
        layout: 'unitformlayout',
        unitType: 'nugget',
        data: req.body,
        errors,
        csrfToken: getCsrfToken(req),
      });
    }

    const nuggetData = {
      title: title.trim(),
      client: client.trim(),
      horizon,
      discipline: discipline?.trim(),
      region: region?.trim(),
estimatedValue: {
  amount: req.body.estimatedValue?.amount ? Number(req.body.estimatedValue.amount) : null,
  currency: req.body.estimatedValue?.currency || 'CAD'
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

    const unitForSuccess = {
      ...nugget.toObject(),
      nugget_title: nugget.title
    };

    const viewLink = `/unitviews/nuggets/view/${nugget._id}`;
    const createLink = `/unitform/form_nugget`;

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'nugget',
      unit: unitForSuccess,
      viewLink,
      createLink,
      dashboardLink: dashboardHomeForUser(req.user),
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
 
    const mainTopics = require('../config/topics');

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

    console.log('RAW req.body.secondary_topics:', req.body.secondary_topics);
console.log('TYPE of req.body.secondary_topics:', typeof req.body.secondary_topics);
console.log('IS ARRAY:', Array.isArray(req.body.secondary_topics));

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
      dashboardLink: dashboardHomeForUser(req.user),
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
let parsedSecondaryTopics = [];

if (Array.isArray(secondary_topics)) {
  parsedSecondaryTopics = secondary_topics.filter(
    topic => typeof topic === 'string' && topic.trim() !== ''
  );
} else if (typeof secondary_topics === 'string' && secondary_topics.trim() !== '') {
  parsedSecondaryTopics = [secondary_topics.trim()];
}

console.log('parsedSecondaryTopics:', parsedSecondaryTopics);

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

console.log('FINAL secondary_topics being saved:', articleData.secondary_topics);

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

// Nuggets don’t really have “published” in the same way.
// If you still want safety, use a simple rule:
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
        dashboardLink: dashboardHomeForUser(req.user),
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
        dashboardLink: dashboardHomeForUser(req.user),
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
        dashboardLink: dashboardHomeForUser(req.user),
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

    if (!requireTermsForPosting(req, res)) return;

    const existingData = req.promptSet || {};
    const selectedBadge = req.session.selectedBadge || {};

    existingData.badge = selectedBadge;
    req.session.selectedBadge = null;

    const mainTopics = require('../config/topics');
    const secondaryTopics = require('../config/topics');

    return res.render('unit_form_views/form_promptset', {
      layout: 'unitformlayout',
      data: existingData,
      mainTopics,
      secondaryTopics,
      characteristics: [
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

// Normalize characteristics checkbox input
if (typeof promptSetData.characteristics === 'string' && promptSetData.characteristics.trim() !== '') {
  promptSetData.characteristics = [promptSetData.characteristics];
} else if (!Array.isArray(promptSetData.characteristics)) {
  promptSetData.characteristics = [];
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
    dashboardLink: dashboardHomeForUser(req.user),
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
  const mainTopics = require('../config/topics');

  try {
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;

    const { _id, fromUpcomingId, existing_document_uploads, ...exerciseData } = req.body;

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

    if (
      typeof exerciseData.secondary_topics === 'string' &&
      exerciseData.secondary_topics.trim() !== ''
    ) {
      exerciseData.secondary_topics = [exerciseData.secondary_topics];
    } else if (!Array.isArray(exerciseData.secondary_topics)) {
      exerciseData.secondary_topics = [];
    }

    exerciseData.author = { id: req.user._id };
    exerciseData.file_format = 'PDF';

    // Preserve existing PDF docs on edit.
    // These may still have public url fields for now.
    let preservedDocuments = [];

    if (existing_document_uploads) {
      try {
        const parsed =
          typeof existing_document_uploads === 'string'
            ? JSON.parse(existing_document_uploads)
            : existing_document_uploads;

        if (Array.isArray(parsed)) {
          preservedDocuments = parsed
            .filter((doc) => {
              const filename = String(doc?.filename || '').toLowerCase();
              const mimetype = String(doc?.mimetype || '').toLowerCase();

              return (
                doc?.filename &&
                (
                  filename.endsWith('.pdf') ||
                  mimetype === 'application/pdf' ||
                  doc?.fileType === 'pdf'
                ) &&
                (doc?.public_id || doc?.url)
              );
            })
            .map((doc) => ({
              public_id: doc.public_id ? String(doc.public_id).trim() : undefined,
              resource_type: doc.resource_type || 'raw',
              type: doc.type || undefined,

              // temporary legacy fallback
              url: doc.url ? String(doc.url).trim() : undefined,

              filename: String(doc.filename).trim(),
              mimetype: 'application/pdf',
              fileType: 'pdf',
            }));
        }
      } catch (err) {
        console.error('Could not parse existing_document_uploads:', err);
      }
    }

    const uploadedFiles = Array.isArray(req.files)
      ? req.files
      : req.files?.document_uploads || [];

    const files = Array.isArray(uploadedFiles)
      ? uploadedFiles
      : [uploadedFiles].filter(Boolean);

try {
  for (const file of files) {
    await validatePdfUpload(file);
  }
} catch (validationError) {
  return res.status(400).render('unit_form_views/form_exercise', {
    layout: 'unitformlayout',
    data: req.body,
    errorMessage: validationError.message,
    mainTopics,
    csrfToken: getCsrfToken(req),
  });
}

    const totalDocumentCount = preservedDocuments.length + files.length;

    if (totalDocumentCount > 3) {
      return res.status(400).render('unit_form_views/form_exercise', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: 'You may upload up to 3 PDF files only.',
        mainTopics,
        csrfToken: getCsrfToken(req),
      });
    }

    let uploadedDocuments = [];

    if (files.length > 0) {
      const uploadPromises = files.map((file) => {
        return new Promise((resolve, reject) => {
          if (!file?.buffer || !file.originalname) {
            return resolve(null);
          }

          const safeOriginalName = file.originalname.replace(/[^\w.\-]/g, '_');
          const safePublicId = `${Date.now()}-${safeOriginalName}`;

          const stream = uploader.upload_stream(
            {
              folder: 'twennie_exercises',
              resource_type: 'raw',
              type: 'authenticated',
              public_id: safePublicId,
              overwrite: false,
            },
            (error, result) => {
              if (error) return reject(error);

              if (!result?.public_id) {
                return reject(
                  new Error(`Cloudinary upload failed for file: ${file.originalname}`)
                );
              }

              resolve({
                public_id: result.public_id,
                resource_type: result.resource_type || 'raw',
                type: result.type || 'authenticated',
                filename: file.originalname,
                mimetype: 'application/pdf',
                fileType: 'pdf',
              });
            }
          );

          stream.end(file.buffer);
        });
      });

      uploadedDocuments = (await Promise.all(uploadPromises)).filter(Boolean);
    }

    exerciseData.document_uploads =
      uploadedDocuments.length > 0
        ? [...preservedDocuments, ...uploadedDocuments]
        : preservedDocuments;

    let exercise;

    if (_id) {
      exercise = await Exercise.findByIdAndUpdate(_id, exerciseData, {
        new: true,
        runValidators: true,
      });

      if (!exercise) {
        throw new Error(`Exercise not found for ID ${_id}.`);
      }

      console.log(`Exercise with ID ${_id} updated successfully.`);
    } else {
      exercise = new Exercise(exerciseData);
      await exercise.save();
      console.log('New exercise created successfully.');
    }

    const isPublished = (() => {
      const status =
        (typeof exercise.status !== 'undefined' ? exercise.status : undefined) ??
        exerciseData.status ??
        exerciseData.publish_status ??
        exercise.is_published ??
        exerciseData.is_published;

      return status === true || String(status).toLowerCase() === 'published';
    })();

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
      }
    }

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'exercise',
      dashboardLink: dashboardHomeForUser(req.user),
      unit: exercise,
      csrfToken: getCsrfToken(req),
    });

  } catch (error) {
    console.error('Error submitting exercise:', error);

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
        errorMessage:
          'Your session has expired or the form took too long to submit. Please refresh and try again.',
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
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;

    const { _id, fromUpcomingId, existing_document_uploads, ...templateData } = req.body;

    const booleanFields = [
      'clarify_topic',
      'produce_deliverables',
      'new_ideas',
      'engaging',
      'permission',
    ];

    booleanFields.forEach((field) => {
      templateData[field] = req.body[field] === 'on';
    });

    if (
      typeof templateData.secondary_topics === 'string' &&
      templateData.secondary_topics.trim() !== ''
    ) {
      templateData.secondary_topics = [templateData.secondary_topics];
    } else if (!Array.isArray(templateData.secondary_topics)) {
      templateData.secondary_topics = [];
    }

    templateData.author = { id: req.user._id };
    templateData.file_format = 'PDF';

    // Preserve existing PDF uploads on edit.
    // Legacy records may still have public url fields for now.
    let preservedDocuments = [];

    if (existing_document_uploads) {
      try {
        const parsed =
          typeof existing_document_uploads === 'string'
            ? JSON.parse(existing_document_uploads)
            : existing_document_uploads;

        if (Array.isArray(parsed)) {
          preservedDocuments = parsed
            .filter((doc) => {
              const filename = String(doc?.filename || '').toLowerCase();
              const mimetype = String(doc?.mimetype || '').toLowerCase();

              return (
                doc?.filename &&
                (
                  filename.endsWith('.pdf') ||
                  mimetype === 'application/pdf' ||
                  doc?.fileType === 'pdf'
                ) &&
                (doc?.public_id || doc?.url)
              );
            })
            .map((doc) => ({
              public_id: doc.public_id ? String(doc.public_id).trim() : undefined,
              resource_type: doc.resource_type || 'raw',
              type: doc.type || undefined,

              // temporary legacy fallback
              url: doc.url ? String(doc.url).trim() : undefined,

              filename: String(doc.filename).trim(),
              mimetype: 'application/pdf',
              fileType: 'pdf',
              role: 'view',
            }));
        }
      } catch (err) {
        console.error('Could not parse existing_document_uploads:', err);
      }
    }

    // New form only has template_pdf now
    const pdfFiles = req.files?.template_pdf || [];
    const files = Array.isArray(pdfFiles)
      ? pdfFiles
      : [pdfFiles].filter(Boolean);

    if (files.length > 1) {
      return res.status(400).render('unit_form_views/form_template', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: 'Please upload only one PDF file.',
        csrfToken: getCsrfToken(req),
      });
    }

    const uploadedPdf = files[0];

    if (!_id && !uploadedPdf) {
      return res.status(400).render('unit_form_views/form_template', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: 'Please upload a PDF file for this template.',
        csrfToken: getCsrfToken(req),
      });
    }

    if (_id && !uploadedPdf && preservedDocuments.length === 0) {
      return res.status(400).render('unit_form_views/form_template', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: 'A template must have one PDF file.',
        csrfToken: getCsrfToken(req),
      });
    }

if (uploadedPdf) {
  try {
    await validatePdfUpload(uploadedPdf);
  } catch (validationError) {
    return res.status(400).render('unit_form_views/form_template', {
      layout: 'unitformlayout',
      data: req.body,
      errorMessage: validationError.message,
      csrfToken: getCsrfToken(req),
    });
  }
}

    const uploadToCloudinary = (file) => {
      return new Promise((resolve, reject) => {
        if (!file?.buffer || !file.originalname) {
          return resolve(null);
        }

        const safeOriginalName = file.originalname.replace(/[^\w.\-]/g, '_');
        const safePublicId = `${Date.now()}-${safeOriginalName}`;

        const stream = uploader.upload_stream(
          {
            resource_type: 'raw',
            type: 'authenticated',
            folder: 'twennie_templates',
            public_id: safePublicId,
            overwrite: false,
          },
          (error, result) => {
            if (error) {
              return reject(new Error('Cloudinary upload failed: ' + error.message));
            }

            if (!result?.public_id) {
              return reject(
                new Error(`Cloudinary upload failed for file: ${file.originalname}`)
              );
            }

            resolve({
              public_id: result.public_id,
              resource_type: result.resource_type || 'raw',
              type: result.type || 'authenticated',
              filename: file.originalname,
              mimetype: 'application/pdf',
              fileType: 'pdf',
              role: 'view',
            });
          }
        );

        stream.end(file.buffer);
      });
    };

    const uploadedDocument = uploadedPdf
      ? await uploadToCloudinary(uploadedPdf)
      : null;

    const finalDocumentUploads = uploadedDocument
      ? [uploadedDocument]
      : preservedDocuments.slice(0, 1);

    let templateDoc;

    if (_id) {
      templateDoc = await Template.findByIdAndUpdate(
        _id,
        {
          ...templateData,
          documentUploads: finalDocumentUploads,
        },
        {
          new: true,
          runValidators: true,
        }
      );

      if (!templateDoc) {
        throw new Error(`Template not found for ID ${_id}.`);
      }

      console.log(`Template with ID ${_id} updated successfully.`);
    } else {
      templateDoc = new Template({
        ...templateData,
        documentUploads: finalDocumentUploads,
      });

      await templateDoc.save();
      console.log('New template created successfully.');
    }

    const isPublished = (() => {
      const status =
        (typeof templateDoc.status !== 'undefined' ? templateDoc.status : undefined) ??
        templateData.status ??
        templateData.publish_status ??
        templateDoc.is_published ??
        templateData.is_published;

      return status === true || String(status).toLowerCase() === 'published';
    })();

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
      }
    }

    return res.render('unit_form_views/unit_success', {
      layout: 'unitformlayout',
      unitType: 'template',
      dashboardLink: dashboardHomeForUser(req.user),
      unit: templateDoc,
      csrfToken: getCsrfToken(req),
    });

  } catch (error) {
    console.error('Error submitting template:', error);

    if (error.name === 'ValidationError') {
      return res.status(400).render('unit_form_views/form_template', {
        layout: 'unitformlayout',
        data: req.body,
        errorMessage: error.message,
        csrfToken: getCsrfToken(req),
      });
    }

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
    console.log('MISSION POST BODY:', req.body);
  try {
    if (!req.user || !req.user._id) {
      throw new Error('User is not authenticated or missing user ID.');
    }

    if (!requireTermsForPosting(req, res)) return;

    const isEdit = !!req.body._id;
    const userId = req.user._id;
    const { fromUpcomingId } = req.body;

    const {
      mission_title,
      badge_name,
      status,
      visibility,
      category,
      purpose,
      summary,
      additional_instructions,
      department_requesting,
      open_to,
      timeframe,
      estimated_effort_hours,
      job_number,
      budget_amount,
      due_date,
    } = req.body;

    let rawTwennieUnits = req.body.twennie_units || [];

    if (!Array.isArray(rawTwennieUnits)) {
      rawTwennieUnits = [rawTwennieUnits];
    }

    const twennie_learning_units = rawTwennieUnits
      .filter(v => v && v.trim() !== '')
      .map(v => {
        const [unit_type, unit_id] = v.split(':');
        return { unit_type, unit_id };
      })
      .filter(u => u.unit_type && u.unit_id)
      .slice(0, 6);

    const errors = [];
    if (!mission_title?.trim()) errors.push('Mission title is required.');
    if (!badge_name?.trim()) errors.push('Mission badge name is required.');
    if (!purpose?.trim()) errors.push('Mission purpose is required.');

    if (errors.length) {
      return res.status(400).render('unit_form_views/form_mission', {
        layout: 'unitformlayout',
        unitType: 'mission',
        data: req.body,
        errors,
        csrfToken: getCsrfToken(req),
      });
    }

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

    let deliverablesChecklist = [];
    if (req.body.deliverables_checklist) {
      deliverablesChecklist = req.body.deliverables_checklist
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
    }

    const baseData = {
      mission_title: (mission_title || '').trim(),
      badge_name: (badge_name || '').trim(),
      status: status || 'one time mission',
      visibility: visibility || 'organization_only',
      category: category || 'internal_improvement',
      purpose: (purpose || '').trim(),
      summary: (summary || '').trim(),
      additional_instructions: (additional_instructions || '').trim(),
      department_requesting: (department_requesting || '').trim(),
      open_to: (open_to || '').trim(),
      timeframe: (timeframe || '').trim(),
      job_number: (job_number || '').trim(),
      budget_amount: (budget_amount || '').trim(),
      estimated_effort_hours: estimated_effort_hours
        ? Number(estimated_effort_hours)
        : undefined,
      due_date: due_date ? new Date(due_date) : undefined,
      task_instructions: taskInstructions,
      deliverables_checklist: deliverablesChecklist,
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
        dashboardLink: dashboardHomeForUser(req.user),
        data: req.body,
        errorMessage: error.message,
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
      


