// controllers/demoController.js
const DemoRequest = require('../models/DemoRequest');

const DEMO_VIEW = 'promo_views/demo';

exports.showDemoForm = (req, res) => {
  res.render(DEMO_VIEW, {
    layout: 'mainlayout',
    csrfToken: req.csrfToken ? req.csrfToken() : null
  });
};

exports.submitDemoRequest = async (req, res) => {
  try {
    const {
      name,
      email,
      organization,
      jobTitle,
      teamSize,
      interestArea,
      message
    } = req.body;

    await DemoRequest.create({
      name: name?.trim(),
      email: email?.trim().toLowerCase(),
      organization: organization?.trim(),
      jobTitle: jobTitle?.trim(),
      teamSize: teamSize?.trim(),
      interestArea: interestArea?.trim(),
      message: message?.trim()
    });

    return res.redirect('/book-a-demo/success');

  } catch (err) {
    console.error('Demo request error:', err);

    return res.status(500).render(DEMO_VIEW, {
      layout: 'mainlayout',
      error: 'Something went wrong. Please try again.',
      csrfToken: req.csrfToken ? req.csrfToken() : null,
      formData: req.body
    });
  }
};


