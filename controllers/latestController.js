const moment = require('moment');
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview');
const PromptSet = require('../models/unit_models/promptset');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const Upcoming = require('../models/unit_models/upcoming');

const MemberProfile = require('../models/profile_models/member_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const LeaderProfile = require('../models/profile_models/leader_profile');

// Helper: get correct icon path based on unit type
function getUnitTypeIcon(type) {
  const icons = {
    article: '/icons/article.svg',
    video: '/icons/video.svg',
    interview: '/icons/interview.svg',
    promptset: '/icons/promptset.svg',
    exercise: '/icons/exercise.svg',
    template: '/icons/template.svg'
  };
  return icons[type] || '/icons/default-icon.svg';
}

// Helper: resolve author name and image
async function resolveAuthorById(authorId) {
  try {
    let profile = await LeaderProfile.findOne({ leaderId: authorId }).select('profileImage name');
    if (profile) return { name: profile.name || 'Leader', image: profile.profileImage || '/images/default-avatar.png' };

    profile = await GroupMemberProfile.findOne({ memberId: authorId }).select('profileImage name');
    if (profile) return { name: profile.name || 'Group Member', image: profile.profileImage || '/images/default-avatar.png' };

    profile = await MemberProfile.findOne({ memberId: authorId }).select('profileImage name');
    if (profile) return { name: profile.name || 'Member', image: profile.profileImage || '/images/default-avatar.png' };
  } catch (err) {
    console.error('Error resolving author profile:', err);
  }
  return { name: 'Unknown Author', image: '/images/default-avatar.png' };
}

// Controller: Get all Twennie-visible units for the "latest" view
exports.getLatestLibraryItems = async (req, res) => {
  console.log("👤 req.user in latestController:", req.user);
  try {
    const [
      articles, videos, interviews, promptsets, exercises, templates,
      upcomingDocs
    ] = await Promise.all([
      Article.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Video.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Interview.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      PromptSet.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Exercise.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Template.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      // Upcoming for "coming soon" section
      Upcoming.find({ status: 'in production', visibility: 'all_members' })
        .sort({ projected_release_at: 1, created_at: -1 })
        .limit(20)
        .lean(),
    ]);

    const allLibraryUnits = [
      ...articles.map(u   => ({ title: u.article_title,   ...u, type: 'article' })),
      ...videos.map(u     => ({ title: u.video_title,     ...u, type: 'video' })),
      ...interviews.map(u => ({ title: u.interview_title, ...u, type: 'interview' })),
      ...promptsets.map(u => ({
        title: u.promptset_title,
        ...u,
        type: 'promptset',
        targetAudience: u.target_audience,
        characteristics: u.characteristics,
        purpose: u.purpose,
        suggestedFrequency: u.suggested_frequency,
      })),
      ...exercises.map(u  => ({ title: u.exercise_title,  ...u, type: 'exercise' })),
      ...templates.map(u  => ({ title: u.template_title,  ...u, type: 'template' })),
    ];

    // newest first
    allLibraryUnits.sort((a, b) => b.updated_at - a.updated_at);

    const startOfThisMonth = moment().startOf('month');
    const startOfLastMonth = moment().subtract(1, 'month').startOf('month');
    const endOfLastMonth   = moment().subtract(1, 'month').endOf('month');

    const thisMonthItems = [];
    const lastMonthItems = [];

    for (const unit of allLibraryUnits) {
      const updatedDate = moment(unit.updated_at);
      const authorId = unit.author?.id || unit.author;

      const author = authorId
        ? await resolveAuthorById(authorId)
        : { name: 'Unknown Author', image: '/images/default-avatar.png' };

      const enriched = {
        ...unit,
        authorName: author.name,
        authorImage: author.image,
        unitTypeIcon: getUnitTypeIcon(unit.type),
        // used by free gate
        isVideoOrArticle: unit.type === 'video' || unit.type === 'article',
      };

      if (updatedDate.isSameOrAfter(startOfThisMonth)) {
        thisMonthItems.push(enriched);
      } else if (updatedDate.isBetween(startOfLastMonth, endOfLastMonth, null, '[]')) {
        lastMonthItems.push(enriched);
      }
    }

    // MFA-safe root flags
    const sessionUser     = req.user || req.session?.user || null;
    const isAuthenticated = res.locals.isAuthenticated === true;
    const membershipType  = sessionUser?.membershipType || null;  // 'leader' | 'group_member' | 'member'
    const accessLevel     = sessionUser?.accessLevel || null;     // 'free_individual' | 'contributor_individual' | 'paid_individual'

    const isLeaderOrGroupMember = membershipType === 'leader' || membershipType === 'group_member';
    const isPaid = accessLevel === 'paid_individual' || accessLevel === 'contributor_individual';
    const isFree = accessLevel === 'free_individual';

    // Stamp flags on EACH item so HBS doesn't need @root
    for (const arr of [thisMonthItems, lastMonthItems]) {
      for (const u of arr) {
        u.isAuthenticated = isAuthenticated;
        u.isLeaderOrGroupMember = isLeaderOrGroupMember;
        u.isPaid = isPaid;
        u.isFree = isFree;
      }
    }

    // Map upcoming docs to the shape the view expects
    const upcomingItems = upcomingDocs.map(u => ({
      _id: u._id,
      unit_type: u.unit_type,          // used by getUnitTypeIcon in the view
      title: u.title,
      long_teaser: u.long_teaser,
      image: u.image || { url: '/images/default-upcoming.png' },
      projected_release_at: u.projected_release_at,
    }));

    return res.render('latest_view/latest_view', {
      layout: 'bytopiclayout',
      upcomingItems,     // ← for the new section
      thisMonthItems,
      lastMonthItems,

      // keep these in case other parts of the template use them
      isAuthenticated,
      membershipType,
      accessLevel,
      isLeaderOrGroupMember,
      isPaid,
      isFree,

      // legacy flag if referenced somewhere else
      loggedIn: isAuthenticated,
    });
  } catch (error) {
    console.error('❌ Error in getLatestLibraryItems:', error);
    return res.status(500).render('error', {
      layout: 'mainlayout',
      title: 'Error loading library',
      message: 'There was a problem loading the latest additions to the library. Please try again later.'
    });
  }
};








