// controllers/tagController.js
const Tag = require('../models/tag');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');
// Unit models (for success page title lookup)
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const PromptSet = require('../models/unit_models/promptset');
const Upcoming = require('../models/unit_models/upcoming');
const Nugget = require('../models/unit_models/nugget');
const Mission = require('../models/unit_models/mission');


/** helper: detect if this came from a standard HTML form */
function isHtmlForm(req) {
  const ct = (req.headers['content-type'] || '').toLowerCase();
  const accept = (req.headers.accept || '').toLowerCase();
  return (
    ct.includes('application/x-www-form-urlencoded') ||
    ct.startsWith('multipart/form-data') ||
    accept.includes('text/html')
  );
}

// ---- Unit type normalization + allow list (add near the top)
// ---- Unit type normalization + allow list (top of file)
const ALLOWED_UNIT_TYPES = new Set([
  'article', 'video', 'interview', 'exercise', 'template',
  'promptset', 'upcoming', 'nugget', 'mission', 'topic'  // topic is handled separately
]);

function canonicalUnitType(t) {
  const n = String(t || '').toLowerCase().trim().replace(/[\s_]+/g, '');
  if (n === 'promptset' || n === 'promptsets') return 'promptset';
  if (n === 'upcoming' || n === 'upcomings')   return 'upcoming';
  if (n === 'nugget'  || n === 'nuggets')      return 'nugget';
  if (n === 'mission' || n === 'missions')     return 'mission';
  if (n === 'article' || n === 'articles')     return 'article';
  if (n === 'video'   || n === 'videos')       return 'video';
  if (n === 'interview' || n === 'interviews') return 'interview';
  if (n === 'exercise'  || n === 'exercises')  return 'exercise';
  if (n === 'template'  || n === 'templates')  return 'template';
  if (n === 'topic'     || n === 'topics')     return 'topic';
  return n;
}

function unitLabelFromType(itemType) {
  const map = {
    article: 'article',
    video: 'video',
    interview: 'interview',
    exercise: 'exercise',
    template: 'template',
    promptset: 'prompt set',
    upcoming: 'upcoming unit',
    nugget: 'nugget',
    mission: 'mission',
    topic: 'topic'
  };
  return map[itemType] || 'unit';
}

async function getUnitTitle(itemType, itemId) {
  try {
    switch (itemType) {
      case 'article': {
        const d = await Article.findById(itemId).select('article_title').lean();
        return d?.article_title || 'Untitled article';
      }
      case 'video': {
        const d = await Video.findById(itemId).select('video_title').lean();
        return d?.video_title || 'Untitled video';
      }
      case 'interview': {
        const d = await Interview.findById(itemId).select('interview_title').lean();
        return d?.interview_title || 'Untitled interview';
      }
      case 'exercise': {
        const d = await Exercise.findById(itemId).select('exercise_title').lean();
        return d?.exercise_title || 'Untitled exercise';
      }
      case 'template': {
        const d = await Template.findById(itemId).select('template_title').lean();
        return d?.template_title || 'Untitled template';
      }
      case 'promptset': {
        const d = await PromptSet.findById(itemId).select('promptset_title').lean();
        return d?.promptset_title || 'Untitled prompt set';
      }
      case 'upcoming': {
        const d = await Upcoming.findById(itemId).select('title').lean();
        return d?.title || 'Untitled upcoming unit';
      }
      case 'nugget': {
        const d = await Nugget.findById(itemId).select('title').lean();
        return d?.title || 'Untitled nugget';
      }
      case 'mission': {
        const d = await Mission.findById(itemId).select('mission_title').lean();
        return d?.mission_title || 'Untitled mission';
      }
      case 'topic':
        return 'Topic';
      default:
        return 'Untitled unit';
    }
  } catch (e) {
    console.error('[tagController] getUnitTitle failed:', itemType, itemId, e.message || e);
    return 'Untitled unit';
  }
}



exports.createTag = async (req, res) => {
  try {
    const fromForm = isHtmlForm(req);

    if (!req.user) {
      return fromForm ? res.redirect('/auth/login')
                      : res.status(401).json({ message: 'User must be logged in to create tags.' });
    }

    let { tagName, itemId, itemType } = req.body;
    itemType = canonicalUnitType(itemType);

const assignedToRaw = req.body.assignedTo || {};
const normalizedAssignedTo = Object.values(assignedToRaw)
  .map(v => ({
    member: v?.member,
    instructions: (v?.instructions || '').trim()
  }))
  .filter(v => v.member);

if (!tagName || !itemId || !itemType) {
  const msg = 'Assignment name, item ID, and item type are required.';
  return fromForm
    ? res.status(400).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Invalid assignment',
        errorMessage: msg
      })
    : res.status(400).json({ message: msg });
}

    if (!ALLOWED_UNIT_TYPES.has(itemType)) {
      const msg = `Unsupported item type: ${itemType}`;
      return fromForm
        ? res.status(400).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Invalid tag', errorMessage: msg
          })
        : res.status(400).json({ message: msg });
    }

    const isTopic = itemType === 'topic';

    // identify creator model
    const userId = req.user._id;
    let userModel = null;
    if (await Member.exists({ _id: userId }))           userModel = 'member';
    else if (await Leader.exists({ _id: userId }))      userModel = 'leader';
    else if (await GroupMember.exists({ _id: userId })) userModel = 'group_member';
    else {
      const msg = 'Invalid user. Unable to create a tag.';
      return fromForm
        ? res.status(403).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Permission denied', errorMessage: msg
          })
        : res.status(403).json({ message: msg });
    }

const cleanName = tagName;
const nameLower = cleanName.toLowerCase();

    let tag = await Tag.findOne({ nameLower, createdBy: userId });

    if (!tag) {
      tag = new Tag({
        name: cleanName,
        nameLower,
        createdBy: userId,
        createdByModel: userModel,
        associatedUnits: isTopic ? [] : [{ item: itemId, unitType: itemType }],
        associatedTopics: isTopic ? [itemId] : [],
        assignedTo: []
      });
    } else {
      const already = isTopic
        ? (tag.associatedTopics || []).some(id => String(id) === String(itemId))
        : (tag.associatedUnits || []).some(u => String(u.item) === String(itemId) && u.unitType === itemType);

      if (!already) {
        if (isTopic) tag.associatedTopics.push(itemId);
        else tag.associatedUnits.push({ item: itemId, unitType: itemType });
      }
    }

    // merge/append leader assignments (optional)
    if (normalizedAssignedTo.length) {
      tag.assignedTo = Array.isArray(tag.assignedTo) ? tag.assignedTo : [];
      for (const entry of normalizedAssignedTo) {
        const idx = tag.assignedTo.findIndex(a => String(a.member) === String(entry.member));
        if (idx === -1) {
          tag.assignedTo.push({ member: entry.member, instructions: entry.instructions || '' });
        } else if (entry.instructions) {
          tag.assignedTo[idx].instructions = entry.instructions;
        }
      }

      if (!isTopic) {
        const hasUnit = (tag.associatedUnits || []).some(
          u => String(u.item) === String(itemId) && u.unitType === itemType
        );
        if (!hasUnit) tag.associatedUnits.push({ item: itemId, unitType: itemType });
      }
    }

    await tag.save();

    // HTML success flows
// HTML success flows
// HTML success flows
if (fromForm && normalizedAssignedTo.length > 0) {
  const assignedIds = normalizedAssignedTo.map(a => String(a.member)).filter(Boolean);

  const [groupMembers, leaders, members] = await Promise.all([
    GroupMember.find({ _id: { $in: assignedIds } }).select('_id name').lean(),
    Leader.find({ _id: { $in: assignedIds } }).select('_id groupLeaderName username').lean(),
    Member.find({ _id: { $in: assignedIds } }).select('_id username').lean()
  ]);

  const nameById = new Map([
    ...groupMembers.map(m => [String(m._id), m.name]),
    ...leaders.map(l => [String(l._id), l.groupLeaderName || l.username || 'Leader']),
    ...members.map(m => [String(m._id), m.username || 'Member'])
  ]);

  const assignedNames = assignedIds
    .map(id => nameById.get(id) || id)
    .filter(Boolean);

  const unitLabel = unitLabelFromType(itemType);
  const unitTitle = await getUnitTitle(itemType, itemId);

  return res.render('unit_views/assign_success', {
    layout: 'unitviewlayout',
    title: 'Assignment Successful',
    unitLabel,
    unitTitle,
    promptSetTitle: unitTitle,
    assignedNames,
    skippedLimitNames: [],
    skippedDupesNames: []
  });
}

// Standard HTML form submission (leader self-tag / member / group member quick-tag)
if (fromForm) {
  const back = req.get('referer');
  return res.redirect(back ? `${back}${back.includes('?') ? '&' : '?'}tag=ok` : '/dashboard/member');
}

// Non-HTML / AJAX
return res.status(200).json({ message: 'Tag saved successfully.', tag });

} catch (error) {
  console.error('❌ Error creating tag:', error);
  console.error('message:', error.message);
  console.error('stack:', error.stack);
  console.error('req.body:', req.body);
  console.error(
    'req.user:',
    req.user
      ? {
          _id: req.user._id,
          membershipType: req.user.membershipType
        }
      : null
  );

  if (error.code) console.error('mongo code:', error.code);
  if (error.keyPattern) console.error('keyPattern:', error.keyPattern);
  if (error.keyValue) console.error('keyValue:', error.keyValue);
  if (error.errors) console.error('validation errors:', error.errors);

  return isHtmlForm(req)
    ? res.status(500).render('member_form_views/error', {
        layout: 'memberformlayout',
        title: 'Error',
        errorMessage: 'An error occurred while creating the assignment.'
      })
    : res.status(500).json({ message: 'Internal server error' });
}
};



exports.completeAssignment = async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'Login required.' });

    const tagId = req.params.tagId;
    const me = String(req.user._id);

    const tag = await Tag.findById(tagId);
    if (!tag) return res.status(404).json({ message: 'Tag not found.' });

    // Only the assignee can complete their own assignment
    const row = (tag.assignedTo || []).find(a => String(a.member) === me);
    if (!row) return res.status(403).json({ message: 'No assignment found for this user.' });

    row.completedAt = new Date();
    await tag.save();

    return res.json({ ok: true, tag });
  } catch (e) {
    console.error('❌ completeAssignment error:', e);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

exports.getAssignedToMe = async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'Login required.' });

    const tags = await Tag.find({ 'assignedTo.member': req.user._id }).lean();
    return res.json(tags);
  } catch (e) {
    console.error('❌ getAssignedToMe error:', e);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

exports.unassignMember = async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'Login required.' });

    const tagId = req.params.tagId;
    const memberId = req.params.memberId;

    const isLeader = await Leader.exists({ _id: req.user._id });
    if (!isLeader) return res.status(403).json({ message: 'Only leaders can unassign.' });

    const tag = await Tag.findById(tagId);
    if (!tag) return res.status(404).json({ message: 'Tag not found.' });

    if (String(tag.createdBy) !== String(req.user._id)) {
      return res.status(403).json({ message: 'Only the creating leader can unassign.' });
    }

    tag.assignedTo = (tag.assignedTo || []).filter(a => String(a.member) !== String(memberId));
    await tag.save();

    return res.json({ ok: true, tag });
  } catch (e) {
    console.error('❌ unassignMember error:', e);
    return res.status(500).json({ message: 'Internal server error' });
  }
};



// GET /tags/item/:itemType/:itemId
// GET /tags/item/:itemType/:itemId
exports.getTagsForItem = async (req, res) => {
  try {
    const itemIdParam = req.params.itemId;
    let itemType = canonicalUnitType(req.params.itemType);

    if (!itemIdParam || !itemType) {
      return res.status(400).json({ message: 'itemId and itemType are required.' });
    }
    if (!ALLOWED_UNIT_TYPES.has(itemType)) {
      return res.status(400).json({ message: `Unsupported item type: ${itemType}` });
    }

    const query = (itemType === 'topic')
      ? { associatedTopics: itemIdParam }
      : { associatedUnits: { $elemMatch: { item: itemIdParam, unitType: itemType } } };

    const projection = {
      name: 1, nameLower: 1, createdBy: 1, createdByModel: 1,
      associatedUnits: 1, associatedTopics: 1, assignedTo: 1,
      createdAt: 1, updatedAt: 1
    };

    const tags = await Tag.find(query).select(projection).lean();
    return res.status(200).json(tags);
  } catch (error) {
    console.error('Error fetching tags for item:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};




exports.getTagsForUser = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: 'User must be logged in to view their tags.' });
    }
    const userId = req.user._id;
    const tags = await Tag.find({ createdBy: userId }).lean();
    return res.status(200).json(tags);
  } catch (error) {
    console.error('Error fetching user tags:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

// controllers/tagController.js
exports.deleteTag = async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ message: 'Login required.' });

    const tagId = req.params.tagId;
    const tag = await Tag.findById(tagId);
    if (!tag) return res.status(404).json({ message: 'Tag not found.' });

    // Only the creator can delete the tag entirely
    if (String(tag.createdBy) !== String(req.user._id)) {
      return res.status(403).json({ message: 'Only the tag creator can delete this tag.' });
    }

    await Tag.findByIdAndDelete(tagId);
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ deleteTag error:', e);
    return res.status(500).json({ message: 'Internal server error' });
  }
};



exports.removeTag = async (req, res) => {
  try {
    const fromForm = isHtmlForm(req);

    if (!req.user) {
      return fromForm ? res.redirect('/auth/login')
                      : res.status(401).json({ message: 'User must be logged in to remove tags.' });
    }

    let { tagId, itemId, itemType } = req.params;
    itemType = canonicalUnitType(itemType);

    if (!tagId || !itemId || !itemType) {
      const msg = 'Tag ID, item ID, and item type are required.';
      return fromForm
        ? res.status(400).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Invalid request', errorMessage: msg
          })
        : res.status(400).json({ message: msg });
    }

    if (!ALLOWED_UNIT_TYPES.has(itemType)) {
      const msg = `Unsupported item type: ${itemType}`;
      return fromForm
        ? res.status(400).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Invalid request', errorMessage: msg
          })
        : res.status(400).json({ message: msg });
    }

    const tag = await Tag.findById(tagId);
    if (!tag) {
      return fromForm
        ? res.status(404).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Not found', errorMessage: 'Tag not found.'
          })
        : res.status(404).json({ message: 'Tag not found.' });
    }

    const userId = String(req.user._id);
    const tagCreatorId = String(tag.createdBy);
    if (userId !== tagCreatorId) {
      const msg = 'Only the tag creator can remove this tag.';
      return fromForm
        ? res.status(403).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Permission denied', errorMessage: msg
          })
        : res.status(403).json({ message: msg });
    }

    let changed = false;

    if (itemType === 'topic') {
      const before = (tag.associatedTopics || []).length;
      tag.associatedTopics = (tag.associatedTopics || []).filter(id => String(id) !== String(itemId));
      changed = changed || (tag.associatedTopics.length !== before);
    } else {
      const before = (tag.associatedUnits || []).length;
      tag.associatedUnits = (tag.associatedUnits || []).filter(
        u => !(String(u.item) === String(itemId) && u.unitType === itemType)
      );
      changed = changed || (tag.associatedUnits.length !== before);
    }

    const isNowEmpty =
      (tag.associatedUnits?.length || 0) === 0 &&
      (tag.associatedTopics?.length || 0) === 0 &&
      (!tag.assignedTo || tag.assignedTo.length === 0);

    if (isNowEmpty) {
      await Tag.findByIdAndDelete(tagId);
      const msg = changed
        ? 'Tag deleted because no associations remain.'
        : 'Tag already had no associations and was deleted.';
      return fromForm
        ? res.redirect((req.get('referer') || '/dashboard/leader') + '?tag=deleted')
        : res.status(200).json({ message: msg, deleted: true });
    }

    if (changed) await tag.save();

    if (fromForm) {
      const back = req.get('referer');
      return res.redirect(back ? `${back}${back.includes('?') ? '&' : '?'}tag=updated` : '/dashboard/leader');
    }
    return res.status(200).json({ message: 'Tag updated successfully.', tag, changed });

  } catch (error) {
    console.error('❌ Error removing tag:', error);
    return isHtmlForm(req)
      ? res.status(500).render('member_form_views/error', {
          layout: 'memberformlayout', title: 'Error',
          errorMessage: 'An error occurred while removing the tag.'
        })
      : res.status(500).json({ message: 'Internal server error' });
  }
};












