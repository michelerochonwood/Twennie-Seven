const mongoose = require('mongoose');
const Leader = require(
  '../models/member_models/leader'
);

const GroupMember = require(
  '../models/member_models/group_member'
);

const Member = require(
  '../models/member_models/member'
);

const Article = require(
  '../models/unit_models/article'
);

const Video = require(
  '../models/unit_models/video'
);

const PromptSet = require(
  '../models/unit_models/promptset'
);

const Interview = require(
  '../models/unit_models/interview'
);

const Exercise = require(
  '../models/unit_models/exercise'
);

const Template = require(
  '../models/unit_models/template'
);

const Nugget = require(
  '../models/unit_models/nugget'
);

const Mission = require(
  '../models/unit_models/mission'
);



const CancelledMember = require(
  '../models/member_models/cancelledmember'
);

const TopicSuggestion = require(
  '../models/topic/topic_suggestion'
);

const DemoRequest = require(
  '../models/DemoRequest'
);

/**
 * Return the date a unit was created.
 *
 * Most current units have createdAt. The ObjectId timestamp
 * provides a fallback for older records.
 * 
 * 
 * 
 */

/**
 * Library unit models that may be approved through
 * the Grand Poobaa dashboard.
 */
const LIBRARY_UNIT_MODELS = {
  article: Article,
  video: Video,
  promptset: PromptSet,
  interview: Interview,
  exercise: Exercise,
  template: Template,
  nugget: Nugget,
  mission: Mission
};


function getUnitCreatedAt(unit) {
  const storedDate =
    unit?.createdAt ||
    unit?.created_at ||
    null;

  if (storedDate) {
    const createdAt = new Date(storedDate);

    if (!Number.isNaN(createdAt.getTime())) {
      return createdAt;
    }
  }

  if (
    unit?._id &&
    typeof unit._id.getTimestamp === 'function'
  ) {
    return unit._id.getTimestamp();
  }

  return null;
}


/**
 * Find the stored author ID across the different unit schemas.
 */


function getUnitAuthorId(unit) {
  const possibleAuthorId =
    unit?.author?.id ||
    unit?.author?._id ||
    unit?.createdBy ||
    unit?.created_by ||
    unit?.submittedBy ||
    unit?.author ||
    null;

  if (
    possibleAuthorId &&
    mongoose.Types.ObjectId.isValid(
      String(possibleAuthorId)
    )
  ) {
    return possibleAuthorId;
  }

  return null;
}


/**
 * Extract the title from any Twennie unit model.
 */
function getUnitTitle(unit) {
  return (
    unit?.article_title ||
    unit?.video_title ||
    unit?.promptset_title ||
    unit?.interview_title ||
    unit?.exercise_title ||
    unit?.template_title ||
    unit?.mission_title ||
    unit?.title ||
    'Untitled Unit'
  );
}


/**
 * Extract the primary topic or classification.
 */
function getUnitMainTopic(unit) {
  return (
    unit?.main_topic ||
    unit?.discipline ||
    unit?.client ||
    unit?.region ||
    'No topic assigned'
  );
}


const grandPoobaaController = {

  /**
 * GET /grand-poobaa
 * Render the Grand Poobaa dashboard.
 */
showDashboard: async (req, res) => {
  try {
    const now = new Date();

    const startOfToday = new Date(now);
    startOfToday.setHours(0, 0, 0, 0);




    const activeDemoQuery = {
      status: {
        $ne: 'completed'
      }
    };


    /**
     * Each model is kept with its normalized unit type.
     *
     * We fetch the newest records from each collection and
     * apply the 30-day cutoff after resolving createdAt.
     * This also supports older units that rely on ObjectId
     * timestamps instead of a stored createdAt field.
     */
    const unitSources = [
      {
        model: Article,
        unitType: 'article'
      },
      {
        model: Video,
        unitType: 'video'
      },
      {
        model: PromptSet,
        unitType: 'promptset'
      },
      {
        model: Interview,
        unitType: 'interview'
      },
      {
        model: Exercise,
        unitType: 'exercise'
      },
      {
        model: Template,
        unitType: 'template'
      },
      {
        model: Nugget,
        unitType: 'nugget'
      },
      {
        model: Mission,
        unitType: 'mission'
      }

    ];


    const [
      topicSuggestions,
      topicSuggestionCount,
      newTopicSuggestionsToday,

      cancelledMembers,
      cancellationCount,
      newCancellationsToday,

      demoRequests,
      demoRequestCount,
      newDemoRequestsToday,

      ...unitCollections
    ] = await Promise.all([
      /**
       * Topic suggestions
       */
      TopicSuggestion.find({
        approved: false
      })
        .sort({
          submittedAt: -1
        })
        .lean(),

      TopicSuggestion.countDocuments({
        approved: false
      }),

      TopicSuggestion.countDocuments({
        approved: false,

        submittedAt: {
          $gte: startOfToday
        }
      }),


      /**
       * Cancelled members
       */
      CancelledMember.find({})
        .sort({
          cancelledAt: -1
        })
        .lean(),

      CancelledMember.countDocuments({}),

      CancelledMember.countDocuments({
        cancelledAt: {
          $gte: startOfToday
        }
      }),


      /**
       * Active demo requests
       */
      DemoRequest.find(activeDemoQuery)
        .sort({
          createdAt: -1
        })
        .lean(),

      DemoRequest.countDocuments(
        activeDemoQuery
      ),

      DemoRequest.countDocuments({
        ...activeDemoQuery,

        createdAt: {
          $gte: startOfToday
        }
      }),


      /**
       * Recently created library units.
       *
       * Fifty per collection provides enough room for the
       * recent-unit dashboard without loading entire
       * collections.
       */
      ...unitSources.map(({ model }) =>
        model
          .find({
            approved: {
              $ne: true
            }
          })
          .sort({
            _id: -1
          })
          .limit(100)
          .lean()
      )
    ]);


    /**
     * Format topic suggestions.
     */
    const formattedTopicSuggestions =
      topicSuggestions.map((suggestion) => ({
        ...suggestion,

        submittedAtDisplay:
          suggestion.submittedAt
            ? new Date(
                suggestion.submittedAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

        submittedAtISO:
          suggestion.submittedAt
            ? new Date(
                suggestion.submittedAt
              ).toISOString()
            : ''
      }));


    /**
     * Format cancelled members.
     */
    const formattedCancelledMembers =
      cancelledMembers.map((member) => ({
        ...member,

        cancelledAtDisplay:
          member.cancelledAt
            ? new Date(
                member.cancelledAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

        cancelledAtISO:
          member.cancelledAt
            ? new Date(
                member.cancelledAt
              ).toISOString()
            : ''
      }));


    /**
     * Format demo requests.
     */
    const formattedDemoRequests =
      demoRequests.map((request) => ({
        ...request,

        status:
          request.status || 'new',

        isNew:
          !request.status ||
          request.status === 'new',

        isScheduled:
          request.status === 'scheduled',

        createdAtDisplay:
          request.createdAt
            ? new Date(
                request.createdAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

        createdAtISO:
          request.createdAt
            ? new Date(
                request.createdAt
              ).toISOString()
            : '',

        scheduledAtDisplay:
          request.scheduledAt
            ? new Date(
                request.scheduledAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

        scheduledAtISO:
          request.scheduledAt
            ? new Date(
                request.scheduledAt
              ).toISOString()
            : ''
      }));


    /**
     * Combine the different unit collections into one
     * normalized array.
     */
    const rawLibraryUnits = [];

unitCollections.forEach(
  (collection, collectionIndex) => {
    const source =
      unitSources[collectionIndex];

    for (const unit of collection) {

      const createdAt =
        getUnitCreatedAt(unit);

      if (!createdAt) {
        continue;
      }



      rawLibraryUnits.push({
        ...unit,

        unitType:
          source.unitType,

        title:
          getUnitTitle(unit),

        mainTopic:
          getUnitMainTopic(unit),

        authorId:
          getUnitAuthorId(unit),

        createdAt
      });

    }
  }
);



    /**
     * Resolve all contributor records in batches rather than
     * making a separate database request for every unit.
     */
    const contributorIds = [
      ...new Set(
        rawLibraryUnits
          .map((unit) =>
            unit.authorId
              ? String(unit.authorId)
              : null
          )
          .filter(Boolean)
      )
    ]
      .filter((id) =>
        mongoose.Types.ObjectId.isValid(id)
      )
      .map((id) =>
        new mongoose.Types.ObjectId(id)
      );


    const [
      unitLeaders,
      unitGroupMembers,
      unitMembers
    ] = contributorIds.length
      ? await Promise.all([
          Leader.find({
            _id: {
              $in: contributorIds
            }
          })
            .select(
              'name username email membershipType'
            )
            .lean(),

          GroupMember.find({
            _id: {
              $in: contributorIds
            }
          })
            .select(
              'name username email membershipType groupName'
            )
            .lean(),

          Member.find({
            _id: {
              $in: contributorIds
            }
          })
            .select(
              'name username email membershipType'
            )
            .lean()
        ])
      : [[], [], []];


    const contributorMap = new Map();


    for (const leader of unitLeaders) {
      contributorMap.set(
        String(leader._id),
        {
          name:
            leader.name ||
            leader.username ||
            'Leader',

          email:
            leader.email || '',

          memberType:
            leader.membershipType ||
            'leader',

          groupName: ''
        }
      );
    }


    for (const groupMember of unitGroupMembers) {
      contributorMap.set(
        String(groupMember._id),
        {
          name:
            groupMember.name ||
            groupMember.username ||
            'Group member',

          email:
            groupMember.email || '',

          memberType:
            groupMember.membershipType ||
            'group member',

          groupName:
            groupMember.groupName || ''
        }
      );
    }


    for (const member of unitMembers) {
      contributorMap.set(
        String(member._id),
        {
          name:
            member.name ||
            member.username ||
            'Member',

          email:
            member.email || '',

          memberType:
            member.membershipType ||
            'member',

          groupName: ''
        }
      );
    }


    /**
     * Prepare the final unit rows for Handlebars.
     */
    const newLibraryUnits =
      rawLibraryUnits
        .map((unit) => {
          const contributor =
            unit.authorId
              ? contributorMap.get(
                  String(unit.authorId)
                )
              : null;

          const embeddedAuthorName =
            unit.author?.name ||
            unit.author_name ||
            unit.authorName ||
            '';

          const embeddedAuthorEmail =
            unit.author?.email ||
            unit.author_email ||
            '';

          return {
            _id:
              unit._id,

            unitType:
              unit.unitType,

            title:
              unit.title,

            mainTopic:
              unit.mainTopic,

            author:
              contributor?.name ||
              embeddedAuthorName ||
              'Unknown author',

            email:
              contributor?.email ||
              embeddedAuthorEmail ||
              '',

            memberType:
              contributor?.memberType ||
              'contributor',

            groupName:
              contributor?.groupName ||
              '',

            createdAtDisplay:
              unit.createdAt.toLocaleDateString(
                'en-CA',
                {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                }
              ),

            createdAtISO:
              unit.createdAt.toISOString(),

            createdAt:
              unit.createdAt
          };
        })
        .sort(
          (a, b) =>
            b.createdAt - a.createdAt
        )
        .slice(0, 100);


    const newLibraryUnitCount =
      newLibraryUnits.length;


    const newLibraryUnitsToday =
      newLibraryUnits.filter(
        (unit) =>
          unit.createdAt >= startOfToday
      ).length;


    const currentDate =
      now.toLocaleDateString('en-CA', {
        month: 'long',
        day: 'numeric',
        year: 'numeric'
      });


    /**
     * Cancelled members remain in the total because the card
     * currently displays the full cancellation archive.
     *
     * New library units are included because they are being
     * presented as content requiring administrative review.
     */
    const totalActionItems =
      topicSuggestionCount +
      cancellationCount +
      demoRequestCount +
      newLibraryUnitCount;


    const newToday =
      newTopicSuggestionsToday +
      newCancellationsToday +
      newDemoRequestsToday +
      newLibraryUnitsToday;


    return res.render(
      'grandpoobaa/grandpoobaa',
      {
        layout:
          'grand-poobaa-layout',

        title:
          'Grand Poobaa Dashboard',

        currentDate,

        totalActionItems,
        newToday,

        // These will be connected later.
        totalMembers: 0,
        totalOrganizations: 0,

        topicSuggestions:
          formattedTopicSuggestions,

        topicSuggestionCount,

        cancelledMembers:
          formattedCancelledMembers,

        cancellationCount,

        demoRequests:
          formattedDemoRequests,

        demoRequestCount,

        techSupportCount: 0,
        techSupportRequests: [],

        newLibraryUnits,
        newLibraryUnitCount,

        csrfToken:
          typeof req.csrfToken === 'function'
            ? req.csrfToken()
            : null,

        user:
          req.user || null,

        timestamp:
          Date.now()
      }
    );
  } catch (error) {
    console.error(
      'Grand Poobaa dashboard error:',
      error
    );

    return res.status(500).render('error', {
      title:
        'Administrative Dashboard Error',

      message:
        'The Grand Poobaa dashboard could not be loaded.',

      timestamp:
        Date.now()
    });
  }
},

/**
 * POST /grand-poobaa/topic-suggestions/:suggestionId/approve
 * Approve a topic suggestion and record its expected
 * library date.
 */
approveTopicSuggestion: async (req, res) => {
  try {
    const { suggestionId } = req.params;
    const { expectedLibraryDate } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(
        suggestionId
      )
    ) {
      return res
        .status(400)
        .send('Invalid topic suggestion ID.');
    }

    if (!expectedLibraryDate) {
      return res.status(400).send(
        'An expected library date is required.'
      );
    }

    const parsedExpectedDate = new Date(
      `${expectedLibraryDate}T12:00:00`
    );

    if (
      Number.isNaN(
        parsedExpectedDate.getTime()
      )
    ) {
      return res.status(400).send(
        'The expected library date is invalid.'
      );
    }

    const approvedSuggestion =
      await TopicSuggestion.findOneAndUpdate(
        {
          _id: suggestionId,
          approved: false
        },

        {
          $set: {
            approved: true,
            approvalDate: new Date(),
            expectedLibraryDate:
              parsedExpectedDate
          }
        },

        {
          new: true,
          runValidators: true
        }
      );

    if (!approvedSuggestion) {
      return res.status(404).send(
        'The topic suggestion was not found or has already been approved.'
      );
    }

    console.log(
      `✅ Topic suggestion approved: ${approvedSuggestion.topicTitle}`
    );

    return res.redirect('/grand-poobaa');
  } catch (error) {
    console.error(
      'Approve topic suggestion error:',
      error
    );

    return res.status(500).send(
      'The topic suggestion could not be approved.'
    );
  }
},


/**
 * POST /grand-poobaa/library-units/:unitId/approve
 * Approve a newly submitted library unit.
 */
/**
 * POST /grand-poobaa/library-units/:unitId/approve
 * Approve a newly submitted library unit.
 */
approveLibraryUnit: async (req, res) => {
  try {
    const { unitId } = req.params;

    const unitType = String(
      req.body.unitType || ''
    )
      .trim()
      .toLowerCase();

    if (
      !mongoose.Types.ObjectId.isValid(
        unitId
      )
    ) {
      return res
        .status(400)
        .send('Invalid library unit ID.');
    }

    const UnitModel =
      LIBRARY_UNIT_MODELS[unitType];

    if (!UnitModel) {
      return res
        .status(400)
        .send('Invalid library unit type.');
    }

    const approvedUnit =
      await UnitModel.findOneAndUpdate(
        {
          _id: unitId,

          status: {
            $ne: 'approved'
          }
        },

        {
          $set: {
            status: 'approved'
          }
        },

        {
          new: true,
          runValidators: true
        }
      );

    if (!approvedUnit) {
      return res.status(404).send(
        'The library unit was not found or has already been approved.'
      );
    }

    console.log(
      `✅ Library unit approved: ${unitType} ${unitId}`
    );

    return res.redirect('/grand-poobaa');
  } catch (error) {
    console.error(
      'Approve library unit error:',
      error
    );

    return res.status(500).send(
      'The library unit could not be approved.'
    );
  }
},
/**
 * POST /grand-poobaa/demo-requests/:requestId/schedule
 * Mark a demo request as scheduled.
 */
scheduleDemoRequest: async (req, res) => {
  try {
    const { requestId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(
        requestId
      )
    ) {
      return res
        .status(400)
        .send('Invalid demo request ID.');
    }

    const demoRequest =
      await DemoRequest.findOneAndUpdate(
        {
          _id: requestId,

          status: {
            $ne: 'completed'
          }
        },

        {
          $set: {
            status: 'scheduled',
            scheduledAt: new Date()
          }
        },

        {
          new: true,
          runValidators: true
        }
      );

    if (!demoRequest) {
      return res.status(404).send(
        'The demo request was not found or has already been completed.'
      );
    }

    console.log(
      `📅 Demo request scheduled: ${demoRequest.name} (${demoRequest.email})`
    );

    return res.redirect('/grand-poobaa');
  } catch (error) {
    console.error(
      'Schedule demo request error:',
      error
    );

    return res.status(500).send(
      'The demo request could not be marked as scheduled.'
    );
  }
},


  /**
   * POST /grand-poobaa/demo-requests/:requestId/complete
   * Mark a demo request as completed.
   */
  completeDemoRequest: async (req, res) => {
    try {
      const { requestId } = req.params;

      if (
        !mongoose.Types.ObjectId.isValid(
          requestId
        )
      ) {
        return res
          .status(400)
          .send('Invalid demo request ID.');
      }

      const demoRequest =
        await DemoRequest.findOneAndUpdate(
          {
            _id: requestId,

            status: {
              $ne: 'completed'
            }
          },

          {
            $set: {
              status: 'completed',
              completedAt: new Date()
            }
          },

          {
            new: true,
            runValidators: true
          }
        );

      if (!demoRequest) {
        return res.status(404).send(
          'The demo request was not found or has already been completed.'
        );
      }

      console.log(
        `✅ Demo request completed: ${demoRequest.name} (${demoRequest.email})`
      );

      return res.redirect('/grand-poobaa');
    } catch (error) {
      console.error(
        'Complete demo request error:',
        error
      );

      return res.status(500).send(
        'The demo request could not be completed.'
      );
    }
  }
};


module.exports = grandPoobaaController;