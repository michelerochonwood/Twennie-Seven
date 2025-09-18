const MemberProfile = require("../models/profile_models/member_profile");
const LeaderProfile = require("../models/profile_models/leader_profile");
const GroupMemberProfile = require("../models/profile_models/groupmember_profile");
const GroupProfile = require("../models/profile_models/group_profile");
const path = require("path");
const fs = require("fs");
const Member = require("../models/member_models/member"); // ✅ Import Member model
const Leader = require("../models/member_models/leader");
const GroupMember = require("../models/member_models/group_member");
const Article = require('../models/unit_models/article');
const Video = require('../models/unit_models/video');
const PromptSet = require('../models/unit_models/promptset');
const Interview = require('../models/unit_models/interview');
const Exercise = require('../models/unit_models/exercise');
const Template = require('../models/unit_models/template');
const Badge = require('../models/prompt_models/promptsetcompletion');
const cloudinary = require('../utils/cloudinary'); // or your exact path
const ProfileSurvey = require("../models/profile_models/profile_survey");




        const topicMappings = {
            'AI in Consulting': 'aiinconsulting',
            'AI in Project Management': 'aiinprojectmanagement',
            'AI in Adult Learning': 'aiinadultlearning',
            'Project Management': 'projectmanagement',
            'Workplace Culture': 'workplaceculture',
            'The Pareto Principle': 'theparetoprinciple',
            'Career Development in Technical Services': 'careerdevelopmentintechnicalservices',
            'Soft Skills in Technical Environments': 'softskillsintechnicalenvironments',
            'Business Development in Technical Services': 'businessdevelopmentintechnicalservices',
            'Finding Projects Before they Become RFPs': 'findingprojectsbeforetheybecomerfps',
            'Un-Commoditizing Your Services by Delivering What Clients Truly Value': 'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue',
            'Proposal Management': 'proposalmanagement',
            'Proposal Strategy': 'proposalstrategy',
            'Storytelling in Technical Marketing': 'storytellingintechnicalmarketing',
            'Client Experience': 'clientexperience',
            'Social Media, Advertising, and Other Mysteries': 'socialmediaadvertisingandothermysteries',
            'Emotional Intelligence': 'emotionalintelligence',
            'Diversity and Inclusion in Consulting': 'diversityandinclusioninconsulting',
            'People Before Profit': 'peoplebeforeprofit',
            'Non-Technical Roles in Technical Environments': 'nontechnicalrolesintechnicalenvironments',
            'Leadership in Technical Services': 'leadershipintechnicalservices',
            'The Advantage of Failure': 'theadvantageoffailure',
            'Social Entrepreneurship': 'socialentrepreneurship',
            'Employee Experience': 'employeeexperience',
            'Project Management Software': 'projectmanagementsoftware',
            'CRM Platforms': 'crmplatforms',
            'Client Feedback Software': 'clientfeedbacksoftware',
            'Mental Health in Consulting Environments': 'mentalhealthinconsultingenvironments',
            'Remote or Hybrid Work': 'remoteorhybridwork',
            'Four Day Work Week': 'fourdayworkweek',
            'The Power of Play in the Workplace': 'thepowerofplayintheworkplace',
            'Team Building in Technical Consulting': 'teambuildingintechnicalconsulting',
        };

const topicViewMappings = {
    'aiinconsulting': 'single_topic_aiconsulting',
    'aiinadultlearning': 'single_topic_ailearn',
    'aiinprojectmanagement': 'single_topic_aiprojectmgmt',
    'businessdevelopmentintechnicalservices': 'single_topic_bd',
    'findingprojectsbeforetheybecomerfps': 'findingprojectsbeforetheybecomerfps',
    'un-commoditizingyourservicesbydeliveringwhatclientstrulyvalue': 'uncommoditizingyourservicesbydeliveringwhatclientstrulyvalue',
    'careerdevelopmentintechnicalservices': 'single_topic_careerdev',
    'clientexperience': 'single_topic_clientex',
    'clientfeedbacksoftware': 'single_topic_clientfeedback',
    'crmplatforms': 'single_topic_crm',
    'diversityandinclusioninconsulting': 'single_topic_diversity',
    'emotionalintelligence': 'single_topic_emotionali',
    'employeeexperience': 'single_topic_employeeex',
    'theadvantageoffailure': 'single_topic_failure',
    'fourdayworkweek': 'single_topic_fourday',
    'leadershipintechnicalservices': 'single_topic_leadership',
    'mentalhealthinconsultingenvironments': 'single_topic_mental',
    'nontechnicalrolesintechnicalenvironments': 'single_topic_nontechnical',
    'theparetoprinciple': 'single_topic_pareto',
    'peoplebeforeprofit': 'single_topic_peoplebefore',
    'thepowerofplayintheworkplace': 'single_topic_play',
    'projectmanagementsoftware': 'single_topic_pmsoftware',
    'projectmanagement': 'single_topic_projectmgmt',
    'proposalmanagement': 'single_topic_proposalmgmt',
    'proposalstrategy': 'single_topic_proposalstrat',
    'remoteorhybridwork': 'single_topic_remote',
    'socialentrepreneurship': 'single_topic_social',
    'socialmediaadvertisingandothermysteries': 'single_topic_socialmedia',
    'softskillsintechnicalenvironments': 'single_topic_softskills',
    'storytellingintechnicalmarketing': 'single_topic_storytelling',
    'teambuildingintechnicalconsulting': 'single_topic_teambuilding',
    'workplaceculture': 'single_topic_workplaceculture'
};

// ✅ Utility: Check Profile Ownership
const checkProfileOwnership = (req, profileOwnerId) => {
    const userId = req.user?._id || req.user?.id;
    return userId?.toString() === profileOwnerId?.toString();
};

function getAllTopics() {
    const topicsFilePath = path.join(__dirname, "../public/data/topics.json");
    if (!fs.existsSync(topicsFilePath)) {
        console.error("topics.json file is missing.");
        return [];
    }

    const topicsData = JSON.parse(fs.readFileSync(topicsFilePath, "utf8"));
    return topicsData.topics.map(topic => topic.title);
}

function getSubtopics(topicTitle) {
    const topicsFilePath = path.join(__dirname, "../public/data/topics.json");
    if (!fs.existsSync(topicsFilePath)) {
        console.error("topics.json file is missing.");
        return [];
    }

    const topicsData = JSON.parse(fs.readFileSync(topicsFilePath, "utf8"));
    const topic = topicsData.topics.find(t => t.title === topicTitle);
    return topic ? topic.subtopics : [];
}

async function resolveAuthorById(authorId) {
    let author = await GroupMember.findById(authorId).select('name profileImage') ||
                 await Leader.findById(authorId).select('groupLeaderName profileImage');
    return author ? { name: author.name || author.groupLeaderName, image: author.profileImage } : { name: 'Unknown Author', image: null };
}



// =========================
// ✅ MEMBER PROFILES
// =========================

// ✅ Show Survey Form (shared route for all users)
const showProfileSurveyForm = async (req, res) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).send("Not authenticated.");
    }

    res.render("profile_views/profile_survey_form", {
      layout: "profilelayout",
      csrfToken: req.csrfToken ? req.csrfToken() : null,
      member: {
        name: user.name || user.username || '',
        email: user.email || user.groupLeaderEmail || ''
      }
    });
  } catch (error) {
    console.error("❌ Error loading profile survey form:", error);
    res.status(500).send("Internal Server Error");
  }
};

// ✅ Handle Survey Submission
const submitProfileSurvey = async (req, res) => {
  try {
    const survey = new ProfileSurvey({
      name: req.body.name,
      email: req.body.email,
      role: Array.isArray(req.body.role) ? req.body.role : [req.body.role],
      wantsProfile: req.body.wantsProfile,
      profileTypes: Array.isArray(req.body.profileTypes) ? req.body.profileTypes : [req.body.profileTypes],
      profileComponents: Array.isArray(req.body.profileComponents) ? req.body.profileComponents : [req.body.profileComponents],
      visibility: req.body.visibility,
      connect: req.body.connect,
      notes: req.body.notes
    });

    await survey.save();

    res.render("profile_views/survey_thankyou", {
      layout: "profilelayout",
      memberName: req.body.name || ""
    });
  } catch (error) {
    console.error("❌ Error saving profile survey:", error);
    res.status(500).send("Internal Server Error");
  }
};




const viewMemberProfile = async (req, res) => {

    try {
      const profile = await MemberProfile.findOne({ memberId: req.params.id });
  
      if (!profile) {
        return res.status(404).send("Profile not found.");
      }
  
      // ✅ Ensure Cloudinary image or fallback
      const safeProfileImage = profile.profileImage?.startsWith("http")
        ? profile.profileImage
        : "https://www.twennie.com/images/default-avatar.png";
  
      const topics = profile.topics || {};
  
      const profileData = {
        profileImage: safeProfileImage,
        name: profile.name || "No Name Provided",
        professionalTitle: profile.professionalTitle || "No Title Provided",
        organization: profile.organization || "No Organization Provided",
        biography: profile.biography || "",
        goals: profile.goals || "",
        topics,
        memberId: profile.memberId.toString()
      };
  
      // ✅ DRY loop to structure selected topics
      const selectedTopics = ["topic1", "topic2", "topic3"].reduce((acc, key) => {
        const title = topics[key];
        acc[key] = title
          ? {
              title,
              subtopics: getSubtopics(title) || [],
              slug: topicMappings[title] || "unknown-topic",
              viewName: topicMappings[title]
                ? topicViewMappings[topicMappings[title]]
                : "not_found"
            }
          : null;
        return acc;
      }, {});
  
      console.log("✅ Member Selected Topics:", selectedTopics);
  
      // ✅ Fetch badges (used for both earned and completed sets)
      const badgeRecords = await Badge.find({ memberId: profile.memberId })
        .populate("promptSetId")
        .lean();
  
      const memberBadges = badgeRecords.map((record) => ({
        earnedBadge: {
          image: record.earnedBadge?.image || "https://www.twennie.com/images/default-badge.png",
          name: record.earnedBadge?.name || "Unknown Badge"
        },
        promptSetTitle: record.promptSetId?.promptset_title || "Unknown Prompt Set",
        mainTopic: record.promptSetId?.main_topic || "No topic"
      }));
  
      console.log("✅ Member Earned Badges:", JSON.stringify(memberBadges, null, 2));

      


      const [memberArticles, memberVideos, memberPromptSets, memberInterviews, memberExercises, memberTemplates] = await Promise.all([
        Article.find({ 'author.id': profile.memberId }),
        Video.find({ 'author.id': profile.memberId }),
        PromptSet.find({ 'author.id': profile.memberId }),
        Interview.find({ 'author.id': profile.memberId }),
        Exercise.find({ 'author.id': profile.memberId }),
        Template.find({ 'author.id': profile.memberId }),
      ]);
      
      const memberUnits = await Promise.all(
        [...memberArticles, ...memberVideos, ...memberPromptSets, ...memberInterviews, ...memberExercises, ...memberTemplates].map(async (unit) => {
          const author = await resolveAuthorById(unit.author?.id || unit.author);
          return {
            unitType: unit.unitType || unit.constructor?.modelName || 'Unknown',
            title: unit.article_title || unit.video_title || unit.promptset_title || unit.interview_title || unit.exercise_title || unit.template_title,
            status: unit.status,
            mainTopic: unit.main_topic,
            _id: unit._id,
            author: author.name
          };
        })
      );
  
      res.render("profile_views/member_profile", {
        layout: "profilelayout",
        member: {
          ...profileData,
          selectedTopics
        },
        memberBadges,
        memberUnits // ✅ This line is critical
      })
    } catch (error) {
      console.error("❌ Error fetching member profile:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  




const editMemberProfile = async (req, res) => {

    try {
      const profile = await MemberProfile.findOne({ memberId: req.params.id });
  
      if (!profile || !checkProfileOwnership(req, profile.memberId)) {
        return res.status(403).send("Unauthorized");
      }
  
      const allTopics = getAllTopics();
  
      res.render("profile_views/memberprofileForm", {
        layout: "profilelayout",
        profile: {
          profileImage: profile.profileImage || "https://www.twennie.com/images/default-avatar.png",
          name: profile.name || "",
          professionalTitle: profile.professionalTitle || "",
          organization: profile.organization || "",
          biography: profile.biography || "",
          goals: profile.goals || "",
          topics: profile.topics || {},
          memberId: profile.memberId
        },
        allTopics,
        csrfToken: req.csrfToken ? req.csrfToken() : null
      });
    } catch (error) {
      console.error("Error loading member edit form:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  



// ✅ Update Member Profile & Redirect
const updateMemberProfile = async (req, res) => {

    try {
      const profile = await MemberProfile.findOne({ memberId: req.params.id });
  
      if (!profile || !checkProfileOwnership(req, profile.memberId)) {
        return res.status(403).send("Unauthorized");
      }
  
      let updatedFields = {
        name: req.body.name,
        professionalTitle: req.body.professionalTitle,
        organization: req.body.organization,
        biography: req.body.biography,
        goals: req.body.goals,
        topics: {
          topic1: req.body.topics?.topic1,
          topic2: req.body.topics?.topic2,
          topic3: req.body.topics?.topic3
        }
      };
  
      // ✅ Handle Cloudinary image upload if new image was submitted
      if (req.file) {
        const result = await cloudinary.uploader.upload_stream(
          {
            folder: 'twennie_profiles',
            public_id: `member_${req.params.id}`,
            overwrite: true,
            resource_type: 'image'
          },
          async (error, result) => {
            if (error) {
              console.error("❌ Cloudinary Upload Error:", error);
              throw new Error("Cloudinary upload failed");
            }
  
            updatedFields.profileImage = result.secure_url;
  
            // Proceed with update after Cloudinary upload
            const updatedProfile = await MemberProfile.findByIdAndUpdate(profile._id, updatedFields, { new: true });
  
            await Member.findOneAndUpdate(
              { _id: req.params.id },
              { $set: { topics: updatedFields.topics } }
            );
  
            return res.redirect(`/profile/member/${req.params.id}`);
          }
        );
  
        // Push file buffer to stream
        const stream = result;
        stream.end(req.file.buffer);
      } else {
        // No image uploaded, proceed with regular update
        const updatedProfile = await MemberProfile.findByIdAndUpdate(profile._id, updatedFields, { new: true });
  
        await Member.findOneAndUpdate(
          { _id: req.params.id },
          { $set: { topics: updatedFields.topics } }
        );
  
        return res.redirect(`/profile/member/${req.params.id}`);
      }
  
    } catch (error) {
      console.error("❌ Error updating member profile:", error);
      const allTopics = getAllTopics();
      res.status(500).render("profile_views/memberprofileForm", {
        layout: "profilelayout",
        profile: req.body,
        allTopics,
        errorMessage: "An error occurred while saving your profile. Please try again."
      });
    }
  };
  
  


// =========================
// ✅ LEADER PROFILES
// =========================



const viewLeaderProfile = async (req, res) => {

    try {
      const profile = await LeaderProfile.findOne({ leaderId: req.params.id });
      const leader = await Leader.findOne({ _id: req.params.id }).populate("members");
      const group = await GroupProfile.findOne({ groupId: req.params.id }).populate("members");
  
      if (!profile) {
        return res.status(404).send("Profile not found.");
      }
  
      // ✅ Safe Cloudinary fallback
      const safeProfileImage = profile.profileImage?.startsWith("http")
        ? profile.profileImage
        : "https://www.twennie.com/images/default-avatar.png";
  
      const topics = profile.topics || {};
  
      const profileData = {
        profileImage: safeProfileImage,
        name: profile.name || "No Name Provided",
        professionalTitle: profile.professionalTitle || "No Title Provided",
        biography: profile.biography || "",
        goals: profile.goals || "",
        groupLeadershipGoals: profile.groupLeadershipGoals || "",
        topics,
        leaderId: profile.leaderId.toString()
      };
  
      // ✅ Get leader's content contributions
      const [leaderArticles, leaderVideos, leaderPromptSets, leaderInterviews, leaderExercises, leaderTemplates] = await Promise.all([
        Article.find({ 'author.id': req.params.id }).lean(),
        Video.find({ 'author.id': req.params.id }).lean(),
        PromptSet.find({ 'author.id': req.params.id }).lean(),
        Interview.find({ 'author.id': req.params.id }).lean(),
        Exercise.find({ 'author.id': req.params.id }).lean(),
        Template.find({ 'author.id': req.params.id }).lean()
      ]);
  
      const leaderUnits = [
        ...leaderArticles.map(unit => ({ unitType: 'article', title: unit.article_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id })),
        ...leaderVideos.map(unit => ({ unitType: 'video', title: unit.video_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id })),
        ...leaderPromptSets.map(unit => ({ unitType: 'promptset', title: unit.promptset_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id })),
        ...leaderInterviews.map(unit => ({ unitType: 'interview', title: unit.interview_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id })),
        ...leaderExercises.map(unit => ({ unitType: 'exercise', title: unit.exercise_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id })),
        ...leaderTemplates.map(unit => ({ unitType: 'template', title: unit.template_title, status: unit.status, mainTopic: unit.main_topic, _id: unit._id }))
      ];
  
      console.log("✅ Leader Units Found:", JSON.stringify(leaderUnits, null, 2));
  
      // ✅ Leader badges
      const badgeRecords = await Badge.find({ memberId: leader._id }).populate("promptSetId").lean();
  
      const leaderBadges = badgeRecords.map(record => ({
        earnedBadge: {
          image: record.earnedBadge?.image || "https://www.twennie.com/images/default-badge.png",
          name: record.earnedBadge?.name || "Unknown Badge"
        },
        promptSetTitle: record.promptSetId?.promptset_title || "Unknown Prompt Set",
        mainTopic: record.promptSetId?.main_topic || "No topic"
      }));
  
      console.log("✅ Leader Earned Badges:", JSON.stringify(leaderBadges, null, 2));
  
      // ✅ Selected topics using DRY reduce
      const selectedTopics = ["topic1", "topic2", "topic3"].reduce((acc, key) => {
        const title = topics[key];
        acc[key] = title
          ? {
              title,
              subtopics: getSubtopics(title) || [],
              slug: topicMappings[title] || "unknown-topic",
              viewName: topicMappings[title]
                ? topicViewMappings[topicMappings[title]]
                : "not_found"
            }
          : null;
        return acc;
      }, {});
  
      console.log("✅ Selected Topics for Leader:", JSON.stringify(selectedTopics));
  
      // ✅ Render view
      res.render("profile_views/leader_profile", {
        layout: "profilelayout",
        leader: {
          ...profileData,
          selectedTopics
        },
        leaderUnits,
        leaderBadges,
        group: group || {},
        groupMembers: leader?.members || []
      });
  
    } catch (error) {
      console.error("❌ Error fetching leader profile:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  



const updateLeaderProfile = async (req, res) => {

    try {
      console.log("🔄 Updating Leader Profile...");
      console.log("Request Body:", req.body);
  
      const profile = await LeaderProfile.findOne({ leaderId: req.params.id });
  
      if (!profile || !checkProfileOwnership(req, profile.leaderId)) {
        return res.status(403).send("Unauthorized");
      }
  
      const updateFields = {
        name: req.body.name,
        professionalTitle: req.body.professionalTitle,
        biography: req.body.biography || "",
        goals: req.body.goals || "",
        groupLeadershipGoals: req.body.groupLeadershipGoals || "",
        topics: {
          topic1: req.body.topics?.topic1,
          topic2: req.body.topics?.topic2,
          topic3: req.body.topics?.topic3
        }
      };
  
      // ✅ Upload image to Cloudinary if one was submitted
      if (req.file) {
        const buffer = req.file.buffer;
        const base64 = buffer.toString("base64");
        const dataUri = `data:${req.file.mimetype};base64,${base64}`;
  
        const result = await cloudinary.uploader.upload(dataUri, {
          folder: "twennie_profiles"
        });
  
        updateFields.profileImage = result.secure_url;
      }
  
      // ✅ Update LeaderProfile
      const updatedProfile = await LeaderProfile.findByIdAndUpdate(
        profile._id,
        updateFields,
        { new: true }
      );
  
      if (!updatedProfile) {
        console.error("❌ Profile not found in `leaderprofiles`.");
        return res.status(404).send("Profile not found.");
      }
  
      // ✅ Sync core fields with Leader model
      const updatedLeader = await Leader.findOneAndUpdate(
        { _id: req.params.id },
        {
          $set: {
            name: updateFields.name,
            professionalTitle: updateFields.professionalTitle,
            topics: updateFields.topics
          }
        },
        { new: true }
      );
  
      if (!updatedLeader) {
        console.error("❌ Leader not found in `leaders`.");
        return res.status(404).send("Leader not found.");
      }
  
      console.log("✅ Leader Profile & Topics Updated Successfully:", updatedProfile, updatedLeader);
  
      res.redirect(`/profile/leader/${req.params.id}`);
    } catch (error) {
      console.error("❌ Error updating leader profile & topics:", error);
      res.status(500).render("profile_views/leaderprofileForm", {
        layout: "profilelayout",
        profile: req.body,
        errorMessage: "An error occurred while saving your profile. Please try again."
      });
    }
  };
  

const editLeaderProfile = async (req, res) => {

    try {
        const profile = await LeaderProfile.findOne({ leaderId: req.params.id });
        const leader = await Leader.findOne({ _id: req.params.id });

        if (!profile || !checkProfileOwnership(req, profile.leaderId)) {
            return res.status(403).send("Unauthorized");
        }

        const allTopics = getAllTopics(); // ✅ Get all topics from topics.json
        console.log("✅ Available Topics:", allTopics);

        res.render("profile_views/leaderprofileForm", {
            layout: "profilelayout",
            profile: {
                profileImage: profile.profileImage || "/images/default-avatar.png",
                name: profile.name || "No Name Provided",
                groupName: leader?.groupName || "No Group Name Provided",
                professionalTitle: profile.professionalTitle || "No Title Provided",
                biography: profile.biography || "",
                goals: profile.goals || "",
                groupLeadershipGoals: profile.groupLeadershipGoals || "", // ✅ Specific to leaders
                topics: profile.topics || {},
                leaderId: profile.leaderId
            },
            allTopics, // ✅ Pass all topics for dropdowns
            csrfToken: req.csrfToken ? req.csrfToken() : null
        });
    } catch (error) {
        console.error("Error loading leader edit form:", error);
        res.status(500).send("Internal Server Error");
    }
};




const viewGroupMemberProfile = async (req, res) => {

    try {
      const profile = await GroupMemberProfile.findOne({ groupMemberId: req.params.id });
      const groupMember = await GroupMember.findOne({ _id: req.params.id });
      const group = await GroupProfile.findOne({ groupId: groupMember?.groupId }).populate("members");
      const leader = await Leader.findOne({ _id: group?.groupId });
  
      if (!profile || !groupMember || !leader) {
        return res.status(404).send("Profile not found.");
      }
  
      // ✅ Handle Cloudinary vs fallback profile image
      const safeProfileImage = profile.profileImage?.startsWith("http")
        ? profile.profileImage
        : "https://www.twennie.com/images/default-avatar.png";
  
      const leaderTopics = leader.topics || {};
  
      const profileData = {
        profileImage: safeProfileImage,
        name: profile.name || "No Name Provided",
        professionalTitle: profile.professionalTitle || "No Title Provided",
        biography: profile.biography || "No biography available.",
        goals: profile.goals || "No goals set.",
        topics: leaderTopics,
        groupMemberId: profile.groupMemberId.toString()
      };
  
      // ✅ Build selected topics with mapping info
      const selectedTopics = ["topic1", "topic2", "topic3"].reduce((acc, key) => {
        const topicTitle = leaderTopics[key];
        acc[key] = topicTitle
          ? {
              title: topicTitle,
              subtopics: getSubtopics(topicTitle) || [],
              slug: topicMappings[topicTitle] || "unknown-topic",
              viewName: topicMappings[topicTitle]
                ? topicViewMappings[topicMappings[topicTitle]]
                : "not_found"
            }
          : null;
        return acc;
      }, {});
  
      console.log("✅ Selected Topics Sent to Group Member Profile View:", selectedTopics);
      console.log("✅ Group Member Data Sent to Profile View:", profileData);
  
      // ✅ Fetch badge records (used for both badges and completions)
      const badgeRecords = await Badge.find({ memberId: groupMember._id })
        .populate("promptSetId")
        .lean();
  
      const memberBadges = badgeRecords.map((record) => ({
        earnedBadge: {
          image: record.earnedBadge?.image || "https://www.twennie.com/images/default-badge.png",
          name: record.earnedBadge?.name || "Unknown Badge"
        },
        promptSetTitle: record.promptSetId?.promptset_title || "Unknown Prompt Set",
        mainTopic: record.promptSetId?.main_topic || "No topic"
      }));
  
      const completedPromptSets = badgeRecords.map((record) => ({
        promptSetTitle: record.promptSetId?.promptset_title || "Unknown Prompt Set",
        completionDate: record.completedAt ? new Date(record.completedAt).toDateString() : "Unknown Date",
        badgeEarned: record.earnedBadge?.name || "No Badge Earned"
      }));
  
      console.log("✅ Group Member Earned Badges:", JSON.stringify(memberBadges, null, 2));
      console.log("✅ Group Member Completed Prompt Sets:", JSON.stringify(completedPromptSets, null, 2));
  
      // ✅ Render the group member profile view
      res.render("profile_views/groupmember_profile", {
        layout: "profilelayout",
        groupMember: {
          ...profileData,
          selectedTopics
        },
        memberBadges,
        completedPromptSets,
        group: group || {},
        groupMembers: group?.members || []
      });
    } catch (error) {
      console.error("❌ Error fetching group member profile:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  





  const editGroupMemberProfile = async (req, res) => {

    try {
      const profile = await GroupMemberProfile.findOne({ groupMemberId: req.params.id });
      const groupMember = await GroupMember.findOne({ _id: req.params.id });
      const group = await GroupProfile.findOne({ groupId: groupMember?.groupId }).populate("members");
      const leader = await Leader.findOne({ _id: group?.groupId });
  
      if (!profile || !groupMember || !leader || !checkProfileOwnership(req, profile.groupMemberId)) {
        return res.status(403).send("Unauthorized");
      }
  
      const allTopics = getAllTopics();
      console.log("✅ Available Topics:", allTopics);
  
      const safeProfileImage = profile.profileImage?.startsWith("http")
        ? profile.profileImage
        : "https://www.twennie.com/images/default-avatar.png";
  
      res.render("profile_views/groupmemberprofileForm", {
        layout: "profilelayout",
        profile: {
          profileImage: safeProfileImage,
          name: profile.name || "No Name Provided",
          professionalTitle: profile.professionalTitle || "No Title Provided",
          biography: profile.biography || "",
          goals: profile.goals || "",
          topics: profile.topics || {},
          groupMemberId: profile.groupMemberId
        },
        groupTopics: leader.topics || {},
        allTopics,
        csrfToken: req.csrfToken ? req.csrfToken() : null
      });
    } catch (error) {
      console.error("Error loading group member edit form:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  




  const updateGroupMemberProfile = async (req, res) => {

    try {
      console.log("🔄 Updating Group Member Profile...");
      console.log("Request Body:", req.body);
  
      const profile = await GroupMemberProfile.findOne({ groupMemberId: req.params.id });
  
      if (!profile || !checkProfileOwnership(req, profile.groupMemberId)) {
        return res.status(403).send("Unauthorized");
      }
  
      // Normalize topic input
      const topics = req.body.topics || {};
      topics.topic1 = topics.topic1 || "";
      topics.topic2 = topics.topic2 || "";
      topics.topic3 = topics.topic3 || "";
  
      const updateFields = {
        name: req.body.name,
        professionalTitle: req.body.professionalTitle,
        biography: req.body.biography || "",
        goals: req.body.goals || "",
        topics
      };
  
      // ✅ Cloudinary image upload if file is present
      if (req.file && req.file.mimetype.startsWith("image/")) {
        const buffer = req.file.buffer;
        const base64 = buffer.toString("base64");
        const dataUri = `data:${req.file.mimetype};base64,${base64}`;
  
        const result = await cloudinary.uploader.upload(dataUri, {
          folder: "twennie_profiles"
        });
  
        updateFields.profileImage = result.secure_url;
      }
  
      const updatedProfile = await GroupMemberProfile.findByIdAndUpdate(
        profile._id,
        updateFields,
        { new: true }
      );
  
      if (!updatedProfile) {
        console.error("❌ Profile not found in `groupmemberprofiles`.");
        return res.status(404).send("Profile not found.");
      }
  
      console.log("✅ Group Member Profile Updated Successfully:", updatedProfile);
  
      res.redirect(`/profile/groupmember/${req.params.id}`);
    } catch (error) {
      console.error("❌ Error updating group member profile:", error);
      res.status(500).render("profile_views/groupmemberprofileForm", {
        layout: "profilelayout",
        profile: req.body,
        errorMessage: "An error occurred while saving your profile. Please try again."
      });
    }
  };
  
  


// =========================
// ✅ GROUP PROFILES
// =========================


const viewGroupProfile = async (req, res) => {

    try {
      const leader = await Leader.findOne({ _id: req.params.id }).populate("members");
      const groupProfile = await GroupProfile.findOne({ groupId: req.params.id });
  
      if (!leader || !groupProfile) {
        return res.status(404).send("Group not found.");
      }
  
      console.log("✅ Leader Data:", JSON.stringify(leader, null, 2));
  
      // ✅ Cloud-safe fallback for group image
      const safeGroupImage = leader.profileImage?.startsWith("http")
        ? leader.profileImage
        : "https://www.twennie.com/images/defaultgroupavatar.jpg";
  
      const groupData = {
        groupImage: safeGroupImage,
        groupName: leader.groupName || "No Group Name Provided",
        organization: leader.organization || "No Organization Provided",
        biography: groupProfile.biography || "No biography available.",
        goals: groupProfile.groupGoals || "No goals set.",
        topics: leader.topics || {},
        leaderId: leader._id.toString()
      };
  
      const leaderData = await resolveAuthorById(leader._id);
      const groupLeader = {
        _id: leader._id,
        name: leaderData.name || leader.groupLeaderName || "Unknown Leader",
        profileImage: leader.profileImage?.startsWith("http")
          ? leader.profileImage
          : "https://www.twennie.com/images/default-avatar.png",
        professionalTitle: leader.professionalTitle || "No Title Provided"
      };
  
      console.log("✅ Group Leader Data:", JSON.stringify(groupLeader, null, 2));
  
      // ✅ Topic structure (DRY)
      const topics = leader.topics || {};
      const selectedTopics = ["topic1", "topic2", "topic3"].reduce((acc, key) => {
        const title = topics[key];
        acc[key] = title
          ? {
              title,
              subtopics: getSubtopics(title) || [],
              slug: topicMappings[title] || "unknown-topic",
              viewName: topicMappings[title]
                ? topicViewMappings[topicMappings[title]]
                : "not_found"
            }
          : null;
        return acc;
      }, {});
  
      console.log("✅ Selected Topics for Group:", selectedTopics);
  
      // ✅ Leader's library units
      const [leaderArticles, leaderVideos, leaderPromptSets, leaderInterviews, leaderExercises, leaderTemplates] = await Promise.all([
        Article.find({ 'author.id': leader._id }).lean(),
        Video.find({ 'author.id': leader._id }).lean(),
        PromptSet.find({ 'author.id': leader._id }).lean(),
        Interview.find({ 'author.id': leader._id }).lean(),
        Exercise.find({ 'author.id': leader._id }).lean(),
        Template.find({ 'author.id': leader._id }).lean()
      ]);
  
      // ✅ Group members' units
      const groupMemberIds = leader.members.map(member => member._id);
      const [memberArticles, memberVideos, memberPromptSets, memberInterviews, memberExercises, memberTemplates] = await Promise.all([
        Article.find({ 'author.id': { $in: groupMemberIds } }).lean(),
        Video.find({ 'author.id': { $in: groupMemberIds } }).lean(),
        PromptSet.find({ 'author.id': { $in: groupMemberIds } }).lean(),
        Interview.find({ 'author.id': { $in: groupMemberIds } }).lean(),
        Exercise.find({ 'author.id': { $in: groupMemberIds } }).lean(),
        Template.find({ 'author.id': { $in: groupMemberIds } }).lean()
      ]);
  
      // ✅ Helper to format units
      const formatUnits = async (units, unitType) => {
        return Promise.all(units.map(async (unit) => {
          const authorData = await resolveAuthorById(unit.author?.id);
          return {
            unitType,
            title: unit.article_title || unit.video_title || unit.promptset_title || unit.interview_title || unit.exercise_title || unit.template_title,
            status: unit.status,
            mainTopic: unit.main_topic,
            _id: unit._id,
            author: authorData.name || "Unknown Author"
          };
        }));
      };
  
      const groupLibraryUnits = [
        ...(await formatUnits(leaderArticles, "article")),
        ...(await formatUnits(leaderVideos, "video")),
        ...(await formatUnits(leaderPromptSets, "promptset")),
        ...(await formatUnits(leaderInterviews, "interview")),
        ...(await formatUnits(leaderExercises, "exercise")),
        ...(await formatUnits(leaderTemplates, "template")),
        ...(await formatUnits(memberArticles, "article")),
        ...(await formatUnits(memberVideos, "video")),
        ...(await formatUnits(memberPromptSets, "promptset")),
        ...(await formatUnits(memberInterviews, "interview")),
        ...(await formatUnits(memberExercises, "exercise")),
        ...(await formatUnits(memberTemplates, "template"))
      ];
  
      console.log("✅ Group Library Units:", JSON.stringify(groupLibraryUnits, null, 2));
  
      // ✅ Badges for leader + group members
      const badgeRecords = await Badge.find({ memberId: { $in: [leader._id, ...groupMemberIds] } }).populate("promptSetId").lean();
  
      const groupBadges = await Promise.all(
        badgeRecords.map(async (record) => {
          const memberData = await resolveAuthorById(record.memberId);
          return {
            earnedBadge: {
              image: record.earnedBadge?.image || "https://www.twennie.com/images/default-badge.png",
              name: record.earnedBadge?.name || "Unknown Badge"
            },
            earnedBy: memberData.name || "Unknown Member",
            promptSetTitle: record.promptSetId?.promptset_title || "Unknown Prompt Set",
            mainTopic: record.promptSetId?.main_topic || "No topic",
            purpose: record.promptSetId?.purpose || "No purpose provided"
          };
        })
      );
  
      console.log("✅ Group Earned Badges:", JSON.stringify(groupBadges, null, 2));
  
      res.render("profile_views/group_profile", {
        layout: "profilelayout",
        group: {
          ...groupData,
          selectedTopics
        },
        groupLeader,
        groupLibraryUnits,
        groupBadges,
        isGroupLeader: req.user && req.user.id === leader._id.toString(),
        groupMembers: leader.members || []
      });
    } catch (error) {
      console.error("❌ Error fetching group profile:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  



  const editGroupProfile = async (req, res) => {

    try {
      const leader = await Leader.findOne({ _id: req.params.id });
  
      if (!leader || req.user.id !== leader._id.toString()) {
        return res.status(403).send("Unauthorized");
      }
  
      const allTopics = getAllTopics();
      console.log("✅ Available Topics:", allTopics);
  
      const safeProfileImage = leader.profileImage?.startsWith("http")
        ? leader.profileImage
        : "https://www.twennie.com/images/defaultgroupavatar.jpg";
  
      res.render("profile_views/groupprofileForm", {
        layout: "profilelayout",
        profile: {
          profileImage: safeProfileImage,
          groupName: leader.groupName || "No Group Name Provided",
          organization: leader.organization || "No Organization Provided",
          biography: leader.biography || "No biography available.",
          goals: leader.goals || "No goals set.",
          topics: leader.topics || {},
          leaderId: leader._id.toString()
        },
        allTopics,
        csrfToken: req.csrfToken ? req.csrfToken() : null
      });
    } catch (error) {
      console.error("❌ Error loading group edit form:", error);
      res.status(500).send("Internal Server Error");
    }
  };
  







  const updateGroupProfile = async (req, res) => {

    try {
      console.log("🔄 Updating Group Profile...");
      console.log("Request Body:", req.body);
  
      const leader = await Leader.findById(req.params.id);
      if (!leader || !checkProfileOwnership(req, leader._id)) {
        return res.status(403).send("Unauthorized");
      }
  
      const topics = req.body.topics || {};
      topics.topic1 = topics.topic1 || "";
      topics.topic2 = topics.topic2 || "";
      topics.topic3 = topics.topic3 || "";
  
      const updateFields = {
        groupName: req.body.groupName,
        organization: req.body.organization || "No Organization Provided",
        biography: req.body.biography || "No biography available.",
        goals: req.body.goals || "No goals set.",
        topics
      };
  
      // ✅ Cloudinary upload if valid image file
      if (req.file && req.file.mimetype.startsWith("image/")) {
        const buffer = req.file.buffer;
        const base64 = buffer.toString("base64");
        const dataUri = `data:${req.file.mimetype};base64,${base64}`;
  
        const result = await cloudinary.uploader.upload(dataUri, {
          folder: "twennie_group_profiles"
        });
  
        updateFields.profileImage = result.secure_url;
      }
  
      // ✅ Update Leader
      const updatedLeader = await Leader.findOneAndUpdate(
        { _id: req.params.id },
        {
          $set: {
            groupName: updateFields.groupName,
            organization: updateFields.organization,
            biography: updateFields.biography,
            goals: updateFields.goals,
            topics: updateFields.topics,
            ...(updateFields.profileImage && { profileImage: updateFields.profileImage })
          }
        },
        { new: true }
      );
  
      if (!updatedLeader) {
        console.error("❌ Group not found in `leaders`.");
        return res.status(404).send("Group not found.");
      }
  
      // ✅ Update GroupProfile
      const updatedGroupProfile = await GroupProfile.findOneAndUpdate(
        { groupId: req.params.id },
        {
          $set: {
            groupName: updateFields.groupName,
            organization: updateFields.organization,
            biography: updateFields.biography,
            groupGoals: updateFields.goals,
            groupTopics: updateFields.topics,
            ...(updateFields.profileImage && { groupImage: updateFields.profileImage })
          }
        },
        { new: true }
      );
  
      if (!updatedGroupProfile) {
        console.error("❌ Group profile not found in `groupprofiles`.");
        return res.status(404).send("Group profile not found.");
      }
  
      console.log("✅ Group Profile Updated:", updatedLeader);
      console.log("✅ GroupProfile Synced:", updatedGroupProfile);
  
      res.redirect(`/profile/group/${req.params.id}`);
    } catch (error) {
      console.error("❌ Error updating group profile:", error);
      res.status(500).render("profile_views/groupprofileForm", {
        layout: "profilelayout",
        profile: req.body,
        errorMessage: "An error occurred while saving your group profile. Please try again."
      });
    }
  };
  
  




// =========================
// ✅ EXPORT ALL FUNCTIONS
// =========================

module.exports = {
    viewMemberProfile,
    viewLeaderProfile,
    viewGroupMemberProfile,
    viewGroupProfile,
    editMemberProfile,
    updateMemberProfile,
    editLeaderProfile,
    updateLeaderProfile,
    editGroupMemberProfile,
    updateGroupMemberProfile,
    editGroupProfile,
    updateGroupProfile,
    submitProfileSurvey,
    showProfileSurveyForm
};






















