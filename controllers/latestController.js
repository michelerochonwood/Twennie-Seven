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
    if (profile) {
      return {
        name: profile.name || 'Leader',
        image: profile.profileImage || '/images/default-avatar.png'
      };
    }

    profile = await GroupMemberProfile.findOne({ memberId: authorId }).select('profileImage name');
    if (profile) {
      return {
        name: profile.name || 'Group Member',
        image: profile.profileImage || '/images/default-avatar.png'
      };
    }

    profile = await MemberProfile.findOne({ memberId: authorId }).select('profileImage name');
    if (profile) {
      return {
        name: profile.name || 'Member',
        image: profile.profileImage || '/images/default-avatar.png'
      };
    }
  } catch (err) {
    console.error('Error resolving author profile:', err);
  }

  return {
    name: 'Unknown Author',
    image: '/images/default-avatar.png'
  };
}

// Helper: build promo CTA button
function buildPromoButton({ isAuthenticated, membershipType, accessLevel, unitType, reviewHref }) {
  if (!isAuthenticated) {
    return {
      text: 'log in to view',
      href: '/auth/login',
      disabled: false
    };
  }

  const isLeaderOrGroupMember =
    membershipType === 'leader' || membershipType === 'group_member';

  const isPaidMember =
    membershipType === 'member' &&
    (accessLevel === 'paid_individual' || accessLevel === 'contributor_individual');

  const isFreeMember =
    membershipType === 'member' && accessLevel === 'free_individual';

  if (isLeaderOrGroupMember || isPaidMember) {
    return {
      text: 'review this unit',
      href: reviewHref,
      disabled: false
    };
  }

  if (isFreeMember) {
    if (unitType === 'video' || unitType === 'article') {
      return {
        text: 'review this unit',
        href: reviewHref,
        disabled: false
      };
    }

    return {
      text: 'membership upgrade required',
      href: null,
      disabled: true
    };
  }

  return {
    text: 'membership upgrade required',
    href: null,
    disabled: true
  };
}

// Controller: Get all Twennie-visible units for the "latest" view
exports.getLatestLibraryItems = async (req, res) => {
  console.log('👤 req.user in latestController:', req.user);

  try {
    const [
      articles,
      videos,
      interviews,
      promptsets,
      exercises,
      templates,
      upcomingDocs
    ] = await Promise.all([
      Article.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Video.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Interview.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      PromptSet.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Exercise.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Template.find({ visibility: 'all_members' }).sort({ updated_at: -1 }).lean(),
      Upcoming.find({ status: 'in production', visibility: 'all_members' })
        .sort({ projected_release_at: 1, created_at: -1 })
        .limit(20)
        .lean()
    ]);

    const allLibraryUnits = [
      ...articles.map((u) => ({
        title: u.article_title,
        ...u,
        type: 'article'
      })),
      ...videos.map((u) => ({
        title: u.video_title,
        ...u,
        type: 'video'
      })),
      ...interviews.map((u) => ({
        title: u.interview_title,
        ...u,
        type: 'interview'
      })),
      ...promptsets.map((u) => ({
        title: u.promptset_title,
        ...u,
        type: 'promptset',
        targetAudience: u.target_audience,
        characteristics: u.characteristics,
        purpose: u.purpose,
        suggestedFrequency: u.suggested_frequency
      })),
      ...exercises.map((u) => ({
        title: u.exercise_title,
        ...u,
        type: 'exercise'
      })),
      ...templates.map((u) => ({
        title: u.template_title,
        ...u,
        type: 'template'
      }))
    ];

    // newest first
    allLibraryUnits.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));

    const startOfThisMonth = moment().startOf('month');
    const startOfLastMonth = moment().subtract(1, 'month').startOf('month');
    const endOfLastMonth = moment().subtract(1, 'month').endOf('month');

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
        isVideoOrArticle: unit.type === 'video' || unit.type === 'article'
      };

      if (updatedDate.isSameOrAfter(startOfThisMonth)) {
        thisMonthItems.push(enriched);
      } else if (updatedDate.isBetween(startOfLastMonth, endOfLastMonth, null, '[]')) {
        lastMonthItems.push(enriched);
      }
    }

    // MFA-safe auth flags
    const sessionUser = req.session?.user || req.user || null;

    const isAuthenticated =
      (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) ||
      !!req.user ||
      !!req.session?.user;

    const membershipType = sessionUser?.membershipType || null;
    const accessLevel = sessionUser?.accessLevel || null;

    const isLeaderOrGroupMember =
      membershipType === 'leader' || membershipType === 'group_member';

    const isPaid =
      accessLevel === 'paid_individual' || accessLevel === 'contributor_individual';

    const isFree = accessLevel === 'free_individual';

    // Stamp flags on each dynamic item so HBS can keep using existing logic
    for (const arr of [thisMonthItems, lastMonthItems]) {
      for (const u of arr) {
        u.isAuthenticated = isAuthenticated;
        u.isLeaderOrGroupMember = isLeaderOrGroupMember;
        u.isPaid = isPaid;
        u.isFree = isFree;
      }
    }

    // Map upcoming docs to the shape the view expects
    const upcomingItems = upcomingDocs.map((u) => ({
      _id: u._id,
      unit_type: u.unit_type,
      title: u.title,
      long_teaser: u.long_teaser,
      image: u.image || { url: '/images/default-upcoming.png' },
      projected_release_at: u.projected_release_at
    }));

    // Hard-coded featured promo units
    const featuredPromoBase = [
      {
        title: 'Never Miss Another RFP\nA Solution to a Pesky Problem',
        unitLabel: 'video',
        unitType: 'video',
        image: '/images/missed RFP.png',
        authorImage: '/images/twenniefounders3.png',
        kicker:
          'Missing an RFP creates panic and wasted effort. A simple internal work order turns monitoring into a structured, accountable task, reducing risk, improving consistency, and preventing avoidable breakdowns in your pursuit process.',
        body:
          'Missing an RFP creates unnecessary stress, lost opportunities, and last-minute chaos that could have been avoided. The issue isn’t effort—it’s structure. Monitoring purchasing sites is often informal, unclear, and easy to overlook, especially when support staff are pulled into urgent work. A simple internal work order changes that. It defines expectations, clarifies instructions, and creates accountability on both sides. It also allows for continuity, backups, and regular improvement.',
        reviewHref: '/unitviews/videos/view/69d82d47d8af4487117da8f5'
      },
      {
        title: 'How to Write an Article in an\nIndustry or Trade Publication',
        unitLabel: 'video',
        unitType: 'video',
        image: '/images/renewmag.png',
        authorImage: '/images/twenniefounders3.pmg',
        kicker:
          'Publishing in trusted industry magazines builds instant credibility, but only if you share insight, not project details. Start with tension, show thinking, and help clients see their own challenges reflected.',
        body:
          'Publishing in a trusted industry magazine can create powerful client moments before you even walk in the room. But it only works if the article delivers insight, not documentation. Clients don’t care about scope, budget, or timelines—they care about how you think. Start with tension, something real they’re dealing with, and use the project as proof, not the focus. When the client becomes the hero and your thinking is clear, the article feels relevant and credible. That’s what makes clients engage, ask questions, and remember you long after the meeting ends.',
        reviewHref: '/unitviews/videos/view/69d6c22cd8af4487117d9c34'
      },
      {
        title: 'Creativity and Innovation\nTesting the Habits of the Greats 1',
        unitLabel: 'prompt set',
        unitType: 'promptset',
        image: '/images/creatives.png',
        authorImage: '/images/twenniefounders3.png',
        kicker:
          'This prompt set introduces proven creative techniques used by history’s most innovative thinkers, helping you break routine patterns, generate new ideas, and apply creativity directly to real-world consulting challenges.',
        body:
          'This prompt set draws from the working habits of some of history’s most creative individuals to demonstrate that creativity is not rare—it is trainable. Through structured exercises inspired by figures like Leonardo da Vinci, Walt Disney, and Albert Einstein, you will experiment with techniques such as reverse thinking, constraint design, cross-disciplinary problem solving, and deliberate disruption.',
        reviewHref: '/unitviews/promptsets/view/69d5251fd412678302354d04'
      }
    ];

    const featuredPromos = featuredPromoBase.map((item) => ({
      ...item,
      button: buildPromoButton({
        isAuthenticated,
        membershipType,
        accessLevel,
        unitType: item.unitType,
        reviewHref: item.reviewHref
      })
    }));

    return res.render('latest_view/latest_view', {
      layout: 'bytopiclayout',

      featuredPromos,
      thisMonthItems,
      lastMonthItems,
      upcomingItems,

      isAuthenticated,
      membershipType,
      accessLevel,
      isLeaderOrGroupMember,
      isPaid,
      isFree,
      loggedIn: isAuthenticated
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
