exports.showBadgesView = (req, res) => {
  res.render('badges_view', { layout: 'badgeslayout' });
};

exports.pickBadge = (req, res) => {
  console.log('✅ Received POST to /badges/pick');
  console.log('Request body:', req.body);

  const { badgePath, badgeName } = req.body;

  if (!badgePath || !badgeName) {
    console.error('❌ Missing badgePath or badgeName');
    return res.status(400).json({ error: 'Badge path and badge name are required.' });
  }

  req.session.selectedBadge = { image: badgePath, name: badgeName };
  console.log('✅ Badge saved to session:', req.session.selectedBadge);

  res.json({ success: true, selectedBadge: req.session.selectedBadge });
};

  
  
  