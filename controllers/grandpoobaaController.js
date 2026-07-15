const mongoose = require('mongoose');

const TopicSuggestion = require('../models/topic/topic_suggestion');

const grandPoobaaController = {
  /**
   * GET /grand-poobaa
   * Render the Grand Poobaa dashboard.
   */
  showDashboard: async (req, res) => {
    try {
      const startOfToday = new Date();
      startOfToday.setHours(0, 0, 0, 0);

      const [
        topicSuggestions,
        topicSuggestionCount,
        newTopicSuggestionsToday
      ] = await Promise.all([
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
        })
      ]);

      const formattedTopicSuggestions = topicSuggestions.map((suggestion) => ({
        ...suggestion,

        submittedAtDisplay: suggestion.submittedAt
          ? new Date(suggestion.submittedAt).toLocaleDateString('en-CA', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            })
          : '',

        submittedAtISO: suggestion.submittedAt
          ? new Date(suggestion.submittedAt).toISOString()
          : ''
      }));

      const currentDate = new Date().toLocaleDateString('en-CA', {
        month: 'long',
        day: 'numeric',
        year: 'numeric'
      });

      const totalActionItems = topicSuggestionCount;

      return res.render('grandpoobaa/grandpoobaa', {
        layout: 'grand-poobaa-layout',
        title: 'Grand Poobaa Dashboard',
        currentDate,

        totalActionItems,
        newToday: newTopicSuggestionsToday,

        // These will be connected as we build each card.
        totalMembers: 0,
        totalOrganizations: 0,

        topicSuggestions: formattedTopicSuggestions,
        topicSuggestionCount,

        cancellationCount: 0,
        demoRequestCount: 0,
        techSupportCount: 0,
        joinRequestCount: 0,

        csrfToken:
          typeof req.csrfToken === 'function'
            ? req.csrfToken()
            : null,

        user: req.user || null,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Grand Poobaa dashboard error:', error);

      return res.status(500).render('error', {
        title: 'Administrative Dashboard Error',
        message: 'The Grand Poobaa dashboard could not be loaded.',
        timestamp: Date.now()
      });
    }
  },


  /**
   * POST /grand-poobaa/topic-suggestions/:suggestionId/approve
   * Approve a topic suggestion and record its expected library date.
   */
  approveTopicSuggestion: async (req, res) => {
    try {
      const { suggestionId } = req.params;
      const { expectedLibraryDate } = req.body;

      if (!mongoose.Types.ObjectId.isValid(suggestionId)) {
        return res.status(400).send('Invalid topic suggestion ID.');
      }

      if (!expectedLibraryDate) {
        return res.status(400).send(
          'An expected library date is required.'
        );
      }

      const parsedExpectedDate = new Date(
        `${expectedLibraryDate}T12:00:00`
      );

      if (Number.isNaN(parsedExpectedDate.getTime())) {
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
              expectedLibraryDate: parsedExpectedDate
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
      console.error('Approve topic suggestion error:', error);

      return res.status(500).send(
        'The topic suggestion could not be approved.'
      );
    }
  }
};

module.exports = grandPoobaaController;