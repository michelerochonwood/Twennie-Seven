// controllers/demoController.js
const DemoRequest = require('../models/DemoRequest');

exports.showDemoForm = (req, res) => {
  res.render('demo/book_demo', {
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
      teamSize,
      interestArea,
      message: message?.trim()
    });

    res.render('demo/book_demo_success', {
      layout: 'mainlayout'
    });

  } catch (err) {
    console.error('Demo request error:', err);

    res.status(500).render('demo/book_demo', {
      layout: 'mainlayout',
      error: 'Something went wrong. Please try again.',
      csrfToken: req.csrfToken ? req.csrfToken() : null,
      formData: req.body
    });
  }
};