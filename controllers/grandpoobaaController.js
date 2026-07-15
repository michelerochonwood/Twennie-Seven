const mongoose = require('mongoose');

const CancelledMember = require(
  '../models/member_models/cancelledmember'
);

const TopicSuggestion = require(
  '../models/topic/topic_suggestion'
);

const DemoRequest = require(
  '../models/DemoRequest'
);


const grandPoobaaController = {
  /**
   * GET /grand-poobaa
   * Render the Grand Poobaa dashboard.
   */
  showDashboard: async (req, res) => {
    try {
      const startOfToday = new Date();
      startOfToday.setHours(0, 0, 0, 0);

      const activeDemoQuery = {
        status: {
          $ne: 'completed'
        }
      };

      const [
        topicSuggestions,
        topicSuggestionCount,
        newTopicSuggestionsToday,

        cancelledMembers,
        cancellationCount,
        newCancellationsToday,

        demoRequests,
        demoRequestCount,
        newDemoRequestsToday
      ] = await Promise.all([
        /**
         * Topic suggestions
         */
        TopicSuggestion.find({
          approved: false
        })
          .sort({ submittedAt: -1 })
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
          .sort({ cancelledAt: -1 })
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

        DemoRequest.countDocuments(activeDemoQuery),

        DemoRequest.countDocuments({
          ...activeDemoQuery,

          createdAt: {
            $gte: startOfToday
          }
        })
      ]);


      /**
       * Format topic suggestions for the view.
       */
      const formattedTopicSuggestions = topicSuggestions.map(
        (suggestion) => ({
          ...suggestion,

          submittedAtDisplay: suggestion.submittedAt
            ? new Date(
                suggestion.submittedAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

          submittedAtISO: suggestion.submittedAt
            ? new Date(
                suggestion.submittedAt
              ).toISOString()
            : ''
        })
      );


      /**
       * Format cancelled members for the view.
       */
      const formattedCancelledMembers = cancelledMembers.map(
        (member) => ({
          ...member,

          cancelledAtDisplay: member.cancelledAt
            ? new Date(
                member.cancelledAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

          cancelledAtISO: member.cancelledAt
            ? new Date(
                member.cancelledAt
              ).toISOString()
            : ''
        })
      );


      /**
       * Format demo requests for the view.
       */
      const formattedDemoRequests = demoRequests.map(
        (request) => ({
          ...request,

          status: request.status || 'new',

          isNew:
            !request.status ||
            request.status === 'new',

          isScheduled:
            request.status === 'scheduled',

          createdAtDisplay: request.createdAt
            ? new Date(
                request.createdAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

          createdAtISO: request.createdAt
            ? new Date(
                request.createdAt
              ).toISOString()
            : '',

          scheduledAtDisplay: request.scheduledAt
            ? new Date(
                request.scheduledAt
              ).toLocaleDateString('en-CA', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              })
            : '',

          scheduledAtISO: request.scheduledAt
            ? new Date(
                request.scheduledAt
              ).toISOString()
            : ''
        })
      );


      const currentDate = new Date().toLocaleDateString(
        'en-CA',
        {
          month: 'long',
          day: 'numeric',
          year: 'numeric'
        }
      );


      const totalActionItems =
        topicSuggestionCount +
        cancellationCount +
        demoRequestCount;


      const newToday =
        newTopicSuggestionsToday +
        newCancellationsToday +
        newDemoRequestsToday;


      return res.render(
        'grandpoobaa/grandpoobaa',
        {
          layout: 'grand-poobaa-layout',
          title: 'Grand Poobaa Dashboard',
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
          joinRequestCount: 0,

          csrfToken:
            typeof req.csrfToken === 'function'
              ? req.csrfToken()
              : null,

          user: req.user || null,
          timestamp: Date.now()
        }
      );
    } catch (error) {
      console.error(
        'Grand Poobaa dashboard error:',
        error
      );

      return res.status(500).render('error', {
        title: 'Administrative Dashboard Error',

        message:
          'The Grand Poobaa dashboard could not be loaded.',

        timestamp: Date.now()
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