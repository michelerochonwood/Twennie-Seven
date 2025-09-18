const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const Interview = require('../models/unit_models/interview'); // Import Interview model
const PromptSet = require('../models/unit_models/promptset');
const Template = require('../models/unit_models/template');
const Exercise = require('../models/unit_models/exercise');

const Leader = require('../models/member_models/leader'); // Import Leader model
const GroupMember = require('../models/member_models/group_member'); // Import Group Member model
const Member = require('../models/member_models/member');
const mongoose = require('mongoose');
const LeaderProfile = require('../models/profile_models/leader_profile');
const GroupMemberProfile = require('../models/profile_models/groupmember_profile');
const MemberProfile = require('../models/profile_models/member_profile');
const sanitizeHtml = require('sanitize-html');
const UpcomingUnit = require('../models/unit_models/upcoming'); // models/unit_models/upcoming.js

// Add this helper at the top of the controller file (outside the viewInterview function)
function convertYouTubeToEmbed(url) {
  if (!url) return null;

  // Match typical YouTube formats like:
  // - https://www.youtube.com/watch?v=VIDEO_ID
  // - https://youtu.be/VIDEO_ID
  // - https://www.youtube.com/embed/VIDEO_ID
  const match = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)([\w-]{11})/);

  return match ? `https://www.youtube.com/embed/${match[1]}` : null;
}


async function resolveAuthorById(authorId) {
  // 1. Check leader profile
  let profile = await LeaderProfile.findOne({ leaderId: authorId }).select('profileImage name organization');
  if (profile) {
    const leader = await Leader.findById(authorId).select('groupName');
    return {
      name: profile.name || 'Leader',
      image: profile.profileImage || '/images/default-avatar.png',
      organization: profile.organization || null,
      groupId: leader?._id || null // treat the leader's own ID as their groupId
    };
  }

  // 2. Check group member profile
  profile = await GroupMemberProfile.findOne({ memberId: authorId }).select('profileImage name');
  if (profile) {
    const member = await GroupMember.findById(authorId).select('groupId organization');
    return {
      name: profile.name || 'Group Member',
      image: profile.profileImage || '/images/default-avatar.png',
      groupId: member?.groupId || null,
      organization: member?.organization || null
    };
  }

  // 3. Check individual member profile
  profile = await MemberProfile.findOne({ memberId: authorId }).select('profileImage name');
  if (profile) {
    const member = await Member.findById(authorId).select('organization');
    return {
      name: profile.name || 'Member',
      image: profile.profileImage || '/images/default-avatar.png',
      organization: member?.organization || null,
      groupId: null
    };
  }

  // 4. Fallback
  return {
    name: 'Unknown Author',
    image: '/images/default-avatar.png',
    organization: null,
    groupId: null
  };
}







module.exports = {
    
viewArticle: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📄 Fetching article with ID: ${id}`);

    // 1) Fetch the article
    const article = await Article.findById(id);
    if (!article) {
      console.warn(`❌ Article with ID ${id} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Article Not Found',
        errorMessage: `The article with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author
    const authorId = (article.author?.id || article.author)?.toString();
    const author = await resolveAuthorById(authorId);
    if (!author) {
      console.error(`❌ Author with ID ${authorId} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this article could not be found.`,
      });
    }

    // Current user helpers
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType;

    // 3) Owner check
    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);
    console.log(`👑 Is owner: ${isOwner}`);

    // 4) Visibility → access
    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (article.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        article.visibility === 'organization_only' &&
        req.user?.organization &&
        author.organization &&
        req.user.organization === author.organization;

      isTeamMatch =
        article.visibility === 'team_only' &&
        req.user?.groupId &&
        author.groupId &&
        req.user.groupId.toString() === author.groupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log("🔒 Access breakdown:");
    console.log("• Org match:", isOrgMatch);
    console.log("• Team match:", isTeamMatch);
    console.log("🔓 Authorized to view full content:", isAuthorizedToViewFullContent);

    // 5) If leader, load group members for assignment UI
    let groupMembers = [];
    let leaderId = undefined;
    let leaderName = undefined;

    if (currentMembership === 'leader' && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId);
      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
        console.log("🧑‍🤝‍🧑 Group members found:", groupMembers);
      }
    }

    // 6) Word count
    const plainText = (article.article_body || '').replace(/<[^>]*>/g, ' ').trim();
    const wordCount = plainText ? plainText.split(/\s+/).filter(Boolean).length : 0;

    // 7) Image URL
    const articleImage = article.image?.url || '/images/default-article.png';

    // 8) Render
    return res.render('unit_views/single_article', {
      layout: 'unitviewlayout',

      // Unit identity & content
      _id: article._id.toString(),
      unitType: 'article',
      article_title: article.article_title,
      short_summary: article.short_summary,
      full_summary: article.full_summary,
      article_body: article.article_body,
      article_image: articleImage,

      // Author card
      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      // Topics
      main_topic: article.main_topic,
      secondary_topics: article.secondary_topics,
      sub_topic: article.sub_topic,

      // UX flags
      word_count: wordCount,
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,
      isLeader: currentMembership === 'leader',
      isGroupMemberOrLeader:
        currentMembership === 'leader' || currentMembership === 'group_member',
      isGroupMemberOrMember:
        currentMembership === 'group_member' || currentMembership === 'member',

      // Leader-only assignment data (undefined if not leader → harmless in template)
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      // CSRF for native form posts
      csrfToken: req.csrfToken(),
    });

  } catch (err) {
    console.error('💥 Error fetching article:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the article.',
    });
  }
},







      
    
    
viewVideo: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🎥 Fetching video with ID: ${id}`);

    // 1) Load the video
    const video = await Video.findById(id);
    if (!video) {
      console.warn(`❌ Video with ID ${id} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Video Not Found',
        errorMessage: `The video with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author (profile for name/image) + id for access checks
    const authorIdRaw = video.author?.id || video.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    const author = await resolveAuthorById(authorId);
    if (!authorId || !author) {
      console.error(`❌ Author with ID ${authorId} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this video could not be found.`,
      });
    }

    // 3) Ownership & current user
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;
    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);
    console.log(`👑 Is owner: ${isOwner}`);

    // 4) Access control (fetch author's org/team from real doc)
    let authorOrg = null;
    let authorGroupId = null;
    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);
    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id; // leaders use their own id for team checks
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (video.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        video.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      isTeamMatch =
        video.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log("🔒 Access breakdown (video):", { isOrgMatch, isTeamMatch, isAuthorizedToViewFullContent });

    // 5) Leader context for assignments
    let groupMembers = [];
    let leaderId;
    let leaderName;
    if (currentMembership === 'leader' && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId);
      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
        console.log("🧑‍🤝‍🧑 Group members found:", groupMembers);
      }
    }

    // 6) Build YouTube embed link
    const embedLink = convertYouTubeToEmbed(video.video_content);

    // 7) Render
    return res.render('unit_views/single_video', {
      layout: 'unitviewlayout',

      // identity & content
      _id: video._id.toString(),
      unitType: 'video',
      video_title: video.video_title,
      short_summary: video.short_summary,
      full_summary: video.full_summary,
      video_content: video.video_content || '',
      embedLink,
      video_url: video.video_url || '/images/valuegroupcont.png',

      // author card
      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      // topics
      main_topic: video.main_topic,
      secondary_topics: video.secondary_topics,
      sub_topic: video.sub_topic,

      // flags
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,
      isLeader: currentMembership === 'leader',
      isGroupMemberOrLeader:
        currentMembership === 'leader' || currentMembership === 'group_member',
      isGroupMemberOrMember:
        currentMembership === 'group_member' || currentMembership === 'member',

      // leader-only assignment data
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      // CSRF
      csrfToken: req.csrfToken(),
    });

  } catch (err) {
    console.error('💥 Error fetching video:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the video.',
    });
  }
},





      
    
    
    


viewInterview: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🎙️ Fetching interview with ID: ${id}`);

    // 1. Fetch the interview
    const interview = await Interview.findById(id);
    if (!interview) {
      console.warn(`❌ Interview with ID ${id} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Interview Not Found',
        errorMessage: `The interview with ID ${id} does not exist.`,
      });
    }

    console.log("✅ Interview found:", interview);

    // 2. Resolve the author
    const authorId = interview.author?.id || interview.author;
    const author = await resolveAuthorById(authorId);
    if (!author) {
      console.error(`❌ Author with ID ${authorId} not found.`);
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this interview could not be found.`,
      });
    }

    // 3. Check if the current user is the owner
    const isOwner = req.user && req.user.id.toString() === authorId.toString();
    console.log(`👑 Is owner: ${isOwner}`);

    // 4. Determine access based on visibility
    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (interview.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        interview.visibility === 'organization_only' &&
        req.user?.organization &&
        author.organization &&
        req.user.organization === author.organization;

      isTeamMatch =
        interview.visibility === 'team_only' &&
        req.user?.groupId &&
        author.groupId &&
        req.user.groupId.toString() === author.groupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log("🔒 Access breakdown:");
    console.log("• Org match:", isOrgMatch);
    console.log("• Team match:", isTeamMatch);
    console.log("🔓 Authorized to view full content:", isAuthorizedToViewFullContent);

    // 5. Get group members and leaderId if applicable
    let groupMembers = [];
    let leaderName = null;
    let leaderId = null;

    if (req.user?.membershipType === 'leader') {
      const leader = await Leader.findById(req.user.id);
      if (leader) {
        groupMembers = await GroupMember.find({ groupId: leader._id })
          .select('_id name')
          .lean();
        leaderName = leader.groupLeaderName || leader.username || 'You';
        leaderId = leader._id.toString();
        console.log("🧑‍🤝‍🧑 Group members found:", groupMembers);
      }
    }

    // ✅ 6. Convert the video link to embed format
    const embedLink = convertYouTubeToEmbed(interview.video_link);

    // 7. Render the view
    res.render('unit_views/single_interview', {
      layout: 'unitviewlayout',
      _id: interview._id.toString(),
      interview_title: interview.interview_title,
      short_summary: interview.short_summary,
      full_summary: interview.full_summary,
      interview_link: interview.video_link || '',
      embedLink,
      interview_content: interview.transcript || "Transcript will be available soon.",
      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },
      main_topic: interview.main_topic,
      secondary_topics: interview.secondary_topics,
      sub_topic: interview.sub_topic,
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: req.isAuthenticated(),
      isLeader: req.user?.membershipType === 'leader',
      isGroupMemberOrLeader:
        req.user?.membershipType === 'leader' || req.user?.membershipType === 'group_member',
      isGroupMemberOrMember:
        req.user?.membershipType === 'group_member' || req.user?.membershipType === 'member',
      groupMembers,
      leaderId: leaderId || req.user._id.toString(), // ✅ Ensures correct leaderId even if fallback
      leaderName: leaderName || req.user.username || 'You',
      csrfToken: req.csrfToken()
    });

  } catch (err) {
    console.error('💥 Error fetching interview:', err.stack || err.message);
    res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the interview.',
    });
  }
},







      
    
    

viewPromptset: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📚 Fetching prompt set with ID: ${id}`);

    // 1) Load the prompt set
    const promptSet = await PromptSet.findById(id);
    if (!promptSet) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Prompt Set Not Found',
        errorMessage: `The prompt set with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author (profile for name/image) + actual doc for org/team checks
    const authorIdRaw = promptSet.author?.id || promptSet.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    const author = await resolveAuthorById(authorId);

    if (!authorId || !author) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this prompt set could not be found.`,
      });
    }

    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);
    const currentMembership = req.user?.membershipType || null;
    const isLeader = currentMembership === 'leader';

    // Fetch the author's org/team from their actual doc
    let authorOrg = null;
    let authorGroupId = null;
    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);
    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id; // leaders use their own id as group id
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    // 3) Additional membership checks
    const isGroupMember = !!(await GroupMember.findById(currentUserId).select('_id'));
    const isPaidIndividual =
      req.user?.membershipType === 'member' &&
      ['paid_individual', 'contributor_individual'].includes(req.user?.accessLevel);

    // 4) Visibility check
    let isAuthorizedToViewFullContent = false;
    if (promptSet.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      const isOrgMatch =
        promptSet.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      const isTeamMatch =
        promptSet.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent =
        isOwner || isLeader || isGroupMember || isPaidIndividual || isOrgMatch || isTeamMatch;
    }

    // 5) Leader context for assignment UI
    let groupMembers = [];
    if (isLeader && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId).select('_id groupLeaderName username').lean();
      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('name _id')
          .lean();
      }
    }

    // 6) Render
    return res.render('unit_views/single_promptset', {
      layout: 'unitviewlayout',
      csrfToken: req.csrfToken(),

      _id: promptSet._id.toString(),
      promptset_title: promptSet.promptset_title,
      short_summary: promptSet.short_summary,
      full_summary: promptSet.full_summary,
      main_topic: promptSet.main_topic,
      secondary_topics: promptSet.secondary_topics,
      sub_topic: promptSet.sub_topic,
      target_audience: promptSet.target_audience,
      characteristics: promptSet.characteristics,
      purpose: promptSet.purpose,
      suggested_frequency: promptSet.suggested_frequency,

      prompts: [
        promptSet.Prompt1, promptSet.Prompt2, promptSet.Prompt3, promptSet.Prompt4, promptSet.Prompt5,
        promptSet.Prompt6, promptSet.Prompt7, promptSet.Prompt8, promptSet.Prompt9, promptSet.Prompt10,
        promptSet.Prompt11, promptSet.Prompt12, promptSet.Prompt13, promptSet.Prompt14, promptSet.Prompt15,
        promptSet.Prompt16, promptSet.Prompt17, promptSet.Prompt18, promptSet.Prompt19, promptSet.Prompt20,
      ],
      prompt_headlines: [
        promptSet.prompt_headline1, promptSet.prompt_headline2, promptSet.prompt_headline3, promptSet.prompt_headline4, promptSet.prompt_headline5,
        promptSet.prompt_headline6, promptSet.prompt_headline7, promptSet.prompt_headline8, promptSet.prompt_headline9, promptSet.prompt_headline10,
        promptSet.prompt_headline11, promptSet.prompt_headline12, promptSet.prompt_headline13, promptSet.prompt_headline14, promptSet.prompt_headline15,
        promptSet.prompt_headline16, promptSet.prompt_headline17, promptSet.prompt_headline18, promptSet.prompt_headline19, promptSet.prompt_headline20,
      ],
      prompt0: promptSet.Prompt0,
      prompt_headline0: promptSet.prompt_headline0,

      options: {
        clarify_topic: promptSet.clarify_topic,
        topics_and_enlightenment: promptSet.topics_and_enlightenment,
        challenge: promptSet.challenge,
        instructions: promptSet.instructions,
        time: promptSet.time,
        permission: promptSet.permission,
      },

      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      // flags
      isOwner,
      isLeader,
      isAuthenticated: typeof req.isAuthenticated === 'function' ? req.isAuthenticated() : !!req.user,
      isAuthorizedToViewFullContent,

      // leader UI data
      groupMembers,
    });

  } catch (err) {
    console.error('Error fetching prompt set:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the prompt set.',
    });
  }
},

    
    
    

    
viewExercise: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📘 Fetching exercise with ID: ${id}`);

    // 1) Load the exercise
    const exercise = await Exercise.findById(id);
    if (!exercise) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Exercise Not Found',
        errorMessage: `The exercise with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve creator profile (name/image)
    const authorIdRaw = exercise.author?.id || exercise.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    if (!authorId) {
      return res.status(500).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Error',
        errorMessage: 'An error occurred while fetching the exercise author.',
      });
    }
    const creator = await resolveAuthorById(authorId);

    // 3) Access checks
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    // Load author's actual doc to read organization / team
    let authorOrg = null;
    let authorGroupId = null;
    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);
    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      // Leaders treat their own _id as groupId for team-only checks
      authorGroupId = authorAsLeader._id;
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (exercise.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        exercise.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      isTeamMatch =
        exercise.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log('🔒 Access breakdown (exercise):', { isOwner, isOrgMatch, isTeamMatch, isAuthorizedToViewFullContent });

    // 4) Leader context for assignments
    const currentMembership = req.user?.membershipType;
    let groupMembers = [];
    let leaderId = undefined;
    let leaderName = undefined;

    if (currentMembership === 'leader' && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId);
      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 5) Normalize document uploads to an array
    const documentUploads = Array.isArray(exercise.document_uploads)
      ? exercise.document_uploads
      : exercise.document_uploads
        ? [exercise.document_uploads]
        : [];

    // 6) Render
    return res.render('unit_views/single_exercise', {
      layout: 'unitviewlayout',

      // identity & content
      _id: exercise._id.toString(),
      unitType: 'exercise',
      exercise_title: exercise.exercise_title,
      short_summary: exercise.short_summary,
      full_summary: exercise.full_summary,
      time_required: exercise.time_required,
      file_format: exercise.file_format,
      document_uploads: documentUploads,

      // creator card
      creator: {
        name: creator.name || 'Unknown Creator',
        image: creator.image || '/images/default-avatar.png',
      },

      // topics
      main_topic: exercise.main_topic,
      secondary_topics: exercise.secondary_topics,
      sub_topic: exercise.sub_topic,

      // flags
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,
      isLeader: currentMembership === 'leader',
      isGroupMemberOrLeader:
        currentMembership === 'leader' || currentMembership === 'group_member',
      isGroupMemberOrMember:
        currentMembership === 'group_member' || currentMembership === 'member',

      // leader-only assignment data
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      // CSRF
      csrfToken: req.csrfToken(),
    });

  } catch (err) {
    console.error('💥 Error fetching exercise:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the exercise.',
    });
  }
},



    
    
    
    
    
viewTemplate: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📄 Fetching template with ID: ${id}`);

    // 1) Load template
    const template = await Template.findById(id);
    if (!template) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Template Not Found',
        errorMessage: `The template with ID ${id} does not exist.`,
      });
    }

    // 2) Resolve author (profile for name/image) + id for access checks
    const authorIdRaw = template.author?.id || template.author;
    const authorId = authorIdRaw ? authorIdRaw.toString() : null;
    const author = await resolveAuthorById(authorId);
    if (!authorId || !author) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Author Not Found',
        errorMessage: `The author associated with this template could not be found.`,
      });
    }

    // 3) Ownership
    const currentUserId = (req.user?._id || req.user?.id)?.toString();
    const currentMembership = req.user?.membershipType || null;
    const isOwner = !!(currentUserId && authorId && currentUserId === authorId);

    // 4) Access control: fetch author's org/team from real doc
    let authorOrg = null;
    let authorGroupId = null;
    const [authorAsLeader, authorAsGroupMember] = await Promise.all([
      Leader.findById(authorId).select('_id organization').lean(),
      GroupMember.findById(authorId).select('_id organization groupId').lean()
    ]);
    if (authorAsLeader) {
      authorOrg = authorAsLeader.organization || null;
      authorGroupId = authorAsLeader._id; // leaders use their own id for team checks
    } else if (authorAsGroupMember) {
      authorOrg = authorAsGroupMember.organization || null;
      authorGroupId = authorAsGroupMember.groupId || null;
    }

    let isAuthorizedToViewFullContent = false;
    let isOrgMatch = false;
    let isTeamMatch = false;

    if (template.visibility === 'all_members') {
      isAuthorizedToViewFullContent = true;
    } else {
      isOrgMatch =
        template.visibility === 'organization_only' &&
        req.user?.organization &&
        authorOrg &&
        req.user.organization === authorOrg;

      isTeamMatch =
        template.visibility === 'team_only' &&
        req.user?.groupId &&
        authorGroupId &&
        req.user.groupId.toString() === authorGroupId.toString();

      isAuthorizedToViewFullContent = isOwner || isOrgMatch || isTeamMatch;
    }

    console.log("🔒 Access breakdown (template):", { isOwner, isOrgMatch, isTeamMatch, isAuthorizedToViewFullContent });

    // 5) Leader context for assignments
    let groupMembers = [];
    let leaderId;
    let leaderName;
    if (currentMembership === 'leader' && currentUserId) {
      const leaderDoc = await Leader.findById(currentUserId);
      if (leaderDoc) {
        groupMembers = await GroupMember.find({ groupId: leaderDoc._id })
          .select('_id name')
          .lean();
        leaderId = leaderDoc._id.toString();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
      }
    }

    // 6) Normalize document uploads → [{ url, filename }]
    const toFilename = (u) => {
      try {
        const last = (u || '').split('/').pop() || 'download';
        return decodeURIComponent(last);
      } catch { return 'download'; }
    };

    let documentUploads = [];
    const rawDocs = template.documentUploads;
    if (Array.isArray(rawDocs)) {
      documentUploads = rawDocs.map(d =>
        typeof d === 'string'
          ? { url: d, filename: toFilename(d) }
          : { url: d.url || '', filename: d.filename || toFilename(d.url || '') }
      );
    } else if (rawDocs) {
      documentUploads = [
        typeof rawDocs === 'string'
          ? { url: rawDocs, filename: toFilename(rawDocs) }
          : { url: rawDocs.url || '', filename: rawDocs.filename || toFilename(rawDocs.url || '') }
      ];
    }

    // 7) Render
    return res.render('unit_views/single_template', {
      layout: 'unitviewlayout',

      // identity & content
      _id: template._id.toString(),
      unitType: 'template',
      template_title: template.template_title,
      short_summary: template.short_summary,
      full_summary: template.full_summary,
      template_content: template.template_content,
      documentUploads,

      // author card
      author: {
        name: author.name || 'Unknown Author',
        image: author.image || '/images/default-avatar.png',
      },

      // topics
      main_topic: template.main_topic,
      secondary_topics: template.secondary_topics,
      sub_topic: template.sub_topic,

      // flags
      isOwner,
      isAuthorizedToViewFullContent,
      isAuthenticated: !!req.user,
      isLeader: currentMembership === 'leader',
      isGroupMemberOrLeader:
        currentMembership === 'leader' || currentMembership === 'group_member',
      isGroupMemberOrMember:
        currentMembership === 'group_member' || currentMembership === 'member',

      // leader-only assignment data
      groupMembers,
      leaderId,
      leaderName: leaderName || req.user?.username || 'You',

      // CSRF
      csrfToken: req.csrfToken(),
    });

  } catch (err) {
    console.error('💥 Error fetching template:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the template.',
    });
  }
},


viewUpcoming: async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🟣 Fetching upcoming unit: ${id}`);

    const upcoming = await UpcomingUnit.findById(id).lean();
    if (!upcoming) {
      return res.status(404).render('unit_views/error', {
        layout: 'unitviewlayout',
        title: 'Upcoming Unit Not Found',
        errorMessage: `The upcoming unit with ID ${id} does not exist.`,
      });
    }

    // If this doc somehow survived publish, bounce to the live unit.
    if (upcoming.status === 'released' && upcoming.published_unit_ref?.id) {
      const pathMap = {
        article: 'articles', video: 'videos', interview: 'interviews',
        exercise: 'exercises', template: 'templates', prompt_set: 'promptsets',
        micro_course: 'microcourses', micro_study: 'microstudies',
      };
      const modelPath = pathMap[upcoming.published_unit_ref.model];
      if (modelPath) return res.redirect(`/${modelPath}/view/${upcoming.published_unit_ref.id}`);
    }

    const isAuthenticated = !!req.user;
    const isLeader = req.user?.membershipType === 'leader';
    const canPublish = isLeader; // leaders see "publish now"

    // Lightweight teaser rule
    const isAuthorizedToViewFullContent =
      upcoming.visibility === 'all_members' ? true : isAuthenticated;

    // Leader context for assign form
    let groupMembers = [];
    let leaderName = null;
    let leaderId = null;

    if (isLeader) {
      // Use req.user.id (your session shim sets both id and _id as strings)
      const leaderDoc = await Leader.findById(req.user.id || req.user._id).select('groupLeaderName username').lean();
      if (leaderDoc) {
        const leaderObjectId = leaderDoc._id;
        groupMembers = await GroupMember.find({ groupId: leaderObjectId })
          .select('_id name')
          .lean();
        leaderName = leaderDoc.groupLeaderName || leaderDoc.username || 'You';
        leaderId = leaderObjectId.toString();
        console.log("🧑‍🤝‍🧑 Group members for upcoming:", groupMembers.length);
      }
    }

    return res.render('unit_views/upcomingunit', {
      layout: 'unitviewlayout',
      _id: upcoming._id.toString(),
      title: upcoming.title,
      teaser: upcoming.teaser,
      long_teaser: upcoming.long_teaser,
      unit_type: upcoming.unit_type,
      main_topic: upcoming.main_topic,
      secondary_topics: upcoming.secondary_topics || [],
      sub_topic: upcoming.sub_topic,
      status: upcoming.status,
      projected_release_at: upcoming.projected_release_at,
      image: upcoming.image || { url: '/images/default-upcoming.png' },
      published_unit_ref: upcoming.published_unit_ref || null,

      // view flags
      isAuthenticated,
      isAuthorizedToViewFullContent,
      isLeader,
      isGroupMemberOrLeader:
        req.user?.membershipType === 'leader' || req.user?.membershipType === 'group_member',
      isGroupMemberOrMember:
        req.user?.membershipType === 'group_member' || req.user?.membershipType === 'member',
      isOwner: false, // upcoming has no author binding

      // leader assign context
      groupMembers,
      leaderId: leaderId || req.user?._id?.toString(),
      leaderName: leaderName || req.user?.username || 'You',

      // publish
      canPublish,

      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('💥 Error fetching upcoming unit:', err.stack || err.message);
    return res.status(500).render('unit_views/error', {
      layout: 'unitviewlayout',
      title: 'Error',
      errorMessage: 'An error occurred while fetching the upcoming unit.',
    });
  }
},





};    