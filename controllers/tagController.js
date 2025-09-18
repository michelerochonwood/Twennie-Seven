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

    if (!req.user) {
      return isHtmlForm(req)
        ? res.redirect('/auth/login')
        : res.status(401).json({ message: 'User must be logged in to create tags.' });
    }

    if (!tagName || !itemId || !itemType) {
      const msg = 'Tag name, item ID, and item type are required.';
      return isHtmlForm(req)
        ? res.status(400).render('member_form_views/error', {
            layout: 'memberformlayout',
            title: 'Invalid tag',
            errorMessage: msg
          })
        : res.status(400).json({ message: msg });
    }

    const userId = req.user._id;
    let userModel = null;
    if (await Member.exists({ _id: userId })) userModel = 'member';
    else if (await Leader.exists({ _id: userId })) userModel = 'leader';
    else if (await GroupMember.exists({ _id: userId })) userModel = 'group_member';
    else {
      const msg = 'Invalid user. Unable to create a tag.';
      return isHtmlForm(req)
        ? res.status(403).render('member_form_views/error', {
            layout: 'memberformlayout',
            title: 'Permission denied',
            errorMessage: msg
          })
        : res.status(403).json({ message: msg });
    }

    const cleanName = tagName.trim();
    let tag = await Tag.findOne({ name: cleanName });

    if (!tag) {
      tag = new Tag({
        name: cleanName,
        createdBy: userId,
        createdByModel: userModel,
        associatedUnits: itemType !== 'topic' ? [{ item: itemId, unitType: itemType }] : [],
        associatedTopics: itemType === 'topic' ? [itemId] : [],
        assignedTo: []
      });
    } else {
      // attach the current unit/topic if not already attached
      const isAlreadyTagged =
        itemType === 'topic'
          ? (tag.associatedTopics || []).some(id => id.toString() === String(itemId))
          : (tag.associatedUnits || []).some(u => u.item.toString() === String(itemId) && u.unitType === itemType);

      if (!isAlreadyTagged) {
        if (itemType === 'topic') tag.associatedTopics.push(itemId);
        else tag.associatedUnits.push({ item: itemId, unitType: itemType });
      }
    }

    // leader assignment flow (optional)
    if (userModel === 'leader' && normalizedAssignedTo.length > 0) {
      const newAssignments = [];
      for (const entry of normalizedAssignedTo) {
        if (entry?.member) {
          const alreadyAssigned = (tag.assignedTo || []).some(
            existing => existing.member.toString() === String(entry.member)
          );
          if (!alreadyAssigned) {
            newAssignments.push({
              member: entry.member,
              instructions: entry.instructions || ''
            });
          }
        }
      }
      if (newAssignments.length) {
        tag.assignedTo = [...(tag.assignedTo || []), ...newAssignments];
        // ensure the unit is present
        const alreadyHasUnit = (tag.associatedUnits || []).some(
          u => u.item.toString() === String(itemId) && u.unitType === itemType
        );
        if (!alreadyHasUnit) {
          tag.associatedUnits.push({ item: itemId, unitType: itemType });
        }
      }
    }

    await tag.save();

    // --- Respond appropriately ---
    const fromForm = isHtmlForm(req);

    // If a leader assigned from an HTML form, keep success view
    if (fromForm && userModel === 'leader' && normalizedAssignedTo.length > 0) {
      return res.render('unit_views/assign_success', { layout: 'unitviewlayout' });
    }

    // For normal (non-assign) HTML form posts, redirect back to the unit page with a toast-hint
    if (fromForm) {
      const referer = req.get('referer');
      if (referer) {
        const sep = referer.includes('?') ? '&' : '?';
        return res.redirect(`${referer}${sep}tag=ok`);
      }

      // fallback by role if no referer
      const role = req.user?.membershipType || 'member';
      const fallback =
        role === 'leader' ? '/dashboard/leader'
        : role === 'group_member' ? '/dashboard/groupmember'
        : '/dashboard/member';
      return res.redirect(fallback);
    }

    // JSON for AJAX clients
    return res.status(200).json({ message: 'Tag saved successfully.', tag });
  } catch (error) {
    console.error('❌ Error creating tag:', error);
    return isHtmlForm(req)
      ? res.status(500).render('member_form_views/error', {
          layout: 'memberformlayout',
          title: 'Error',
          errorMessage: 'An error occurred while creating the tag.'
        })
      : res.status(500).json({ message: 'Internal server error' });
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
    // group members can remove only tags they created
    const isGroupMember = !!(await GroupMember.exists({ _id: userId }));
    if (isGroupMember && userId !== tagCreatorId) {
      console.warn(`🚫 Group member ${userId} attempted to remove tag created by ${tagCreatorId}`);
      return res.status(403).json({ message: 'Group members can only remove tags they created.' });
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










