const grandPoobaaRoutes = require('./routes/grandpoobaaRoutes');


const grandPoobaaController = {
  showDashboard: async (req, res) => {
    try {
      const currentDate = new Date().toLocaleDateString('en-CA', {
        month: 'long',
        day: 'numeric',
        year: 'numeric'
      });

      return res.render('grandpoobaa/grandpoobaa', {
        layout: 'grand-poobaa-layout',
        title: 'Grand Poobaa Dashboard',
        currentDate,

        // Placeholder values until the database queries are connected.
        totalActionItems: 0,
        newToday: 0,
        totalMembers: 0,
        totalOrganizations: 0,

        topicSuggestionCount: 0,
        cancellationCount: 0,
        demoRequestCount: 0,
        techSupportCount: 0,
        joinRequestCount: 0,

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
  }
};

module.exports = grandPoobaaController;