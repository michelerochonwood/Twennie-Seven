// controllers/tagController.js
const Tag = require('../models/tag');
const Member = require('../models/member_models/member');
const Leader = require('../models/member_models/leader');
const GroupMember = require('../models/member_models/group_member');

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

exports.createTag = async (req, res) => {
  try {
    const { tagName, itemId, itemType } = req.body;
    const assignedToRaw = req.body.assignedTo || {};
    const normalizedAssignedTo = Object.values(assignedToRaw || {});
    const fromForm = isHtmlForm(req);

    if (!req.user) {
      return fromForm ? res.redirect('/auth/login')
                      : res.status(401).json({ message: 'User must be logged in to create tags.' });
    }

    // Basic validation
    if (!tagName || !itemId || !itemType) {
      const msg = 'Tag name, item ID, and item type are required.';
      return fromForm
        ? res.status(400).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Invalid tag', errorMessage: msg
          })
        : res.status(400).json({ message: msg });
    }

    // Allow either a UNIT_TYPES item or 'topic'
    const isTopic = itemType === 'topic';

    const userId = req.user._id;
    let userModel = null;
    if (await Member.exists({ _id: userId })) userModel = 'member';
    else if (await Leader.exists({ _id: userId })) userModel = 'leader';
    else if (await GroupMember.exists({ _id: userId })) userModel = 'group_member';
    else {
      const msg = 'Invalid user. Unable to create a tag.';
      return fromForm
        ? res.status(403).render('member_form_views/error', {
            layout: 'memberformlayout', title: 'Permission denied', errorMessage: msg
          })
        : res.status(403).json({ message: msg });
    }

    const cleanName = String(tagName).trim();
    const nameLower = cleanName.toLowerCase();

    // IMPORTANT: find/create ONLY within the current creator’s namespace
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
      // attach the current unit/topic if not already attached
      const already = isTopic
        ? (tag.associatedTopics || []).some(id => String(id) === String(itemId))
        : (tag.associatedUnits || []).some(u => String(u.item) === String(itemId) && u.unitType === itemType);

      if (!already) {
        if (isTopic) tag.associatedTopics.push(itemId);
        else tag.associatedUnits.push({ item: itemId, unitType: itemType });
      }
    }

    // leader assignment flow (optional)
const newAssignments = [];
for (const entry of normalizedAssignedTo) {
  if (!entry?.member) continue;

  const idx = (tag.assignedTo || []).findIndex(
    a => String(a.member) === String(entry.member)
  );

  if (idx === -1) {
    newAssignments.push({
      member: entry.member,
      instructions: entry.instructions || ''
    });
  } else {
    // Update instructions if provided
    if (entry.instructions && entry.instructions.trim()) {
      tag.assignedTo[idx].instructions = entry.instructions.trim();
    }
  }
}

if (newAssignments.length) {
  tag.assignedTo = [...(tag.assignedTo || []), ...newAssignments];
}

// ensure the unit is present if assigning on it (non-topic only)
if (!isTopic) {
  const hasUnit = (tag.associatedUnits || []).some(
    u => String(u.item) === String(itemId) && u.unitType === itemType
  );
  if (!hasUnit) tag.associatedUnits.push({ item: itemId, unitType: itemType });
}


    await tag.save();

    // HTML success flows
    if (fromForm && userModel === 'leader' && normalizedAssignedTo.length > 0) {
      return res.render('unit_views/assign_success', { layout: 'unitviewlayout' });
    }
    if (fromForm) {
      const referer = req.get('referer');
      if (referer) {
        const sep = referer.includes('?') ? '&' : '?';
        return res.redirect(`${referer}${sep}tag=ok`);
      }
      const role = req.user?.membershipType || 'member';
      const fallback =
        role === 'leader' ? '/dashboard/leader'
        : role === 'group_member' ? '/dashboard/groupmember'
        : '/dashboard/member';
      return res.redirect(fallback);
    }

    // JSON
    return res.status(200).json({ message: 'Tag saved successfully.', tag });
  } catch (error) {
    console.error('❌ Error creating tag:', error);
    return isHtmlForm(req)
      ? res.status(500).render('member_form_views/error', {
          layout: 'memberformlayout', title: 'Error',
          errorMessage: 'An error occurred while creating the tag.'
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

    // Only group members have leader assignments; others will just see empty
    const isGroupMember = await GroupMember.exists({ _id: req.user._id });
    if (!isGroupMember) return res.json([]);

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



exports.getTagsForItem = async (req, res) => {
  try {
    const { itemId, itemType } = req.params;

    const tags =
      itemType === 'topic'
        ? await Tag.find({ associatedTopics: itemId })
        : await Tag.find({ associatedUnits: { $elemMatch: { item: itemId, unitType: itemType } } });

    return res.status(200).json(tags);
  } catch (error) {
    console.error('Error fetching tags:', error);
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
    const { tagId, itemId, itemType } = req.params;

    if (!req.user) {
      return res.status(401).json({ message: 'User must be logged in to remove tags.' });
    }

    const userId = String(req.user._id);
    const tag = await Tag.findById(tagId);
    if (!tag) {
      return res.status(404).json({ message: 'Tag not found.' });
    }

const tagCreatorId = String(tag.createdBy);

// Only the creator of the tag may remove it from a unit/topic (applies to all roles)
if (userId !== tagCreatorId) {
  console.warn(`🚫 User ${userId} attempted to remove tag created by ${tagCreatorId}`);
  return res.status(403).json({ message: 'Only the tag creator can remove this tag.' });
}

    if (itemType === 'topic') {
      tag.associatedTopics = (tag.associatedTopics || []).filter(id => String(id) !== String(itemId));
    } else {
      tag.associatedUnits = (tag.associatedUnits || []).filter(
        u => !(String(u.item) === String(itemId) && u.unitType === itemType)
      );
    }

    const isNowEmpty =
      (tag.associatedUnits?.length || 0) === 0 &&
      (tag.associatedTopics?.length || 0) === 0 &&
      (!tag.assignedTo || tag.assignedTo.length === 0);

    if (isNowEmpty) {
      await Tag.findByIdAndDelete(tagId);
      console.log(`🗑️ Tag ${tagId} deleted (no associations remain).`);
      return res.status(200).json({ message: 'Tag deleted because no associations remain.' });
    }

    await tag.save();
    return res.status(200).json({ message: 'Tag updated successfully.', tag });
  } catch (error) {
    console.error('❌ Error removing tag:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};










