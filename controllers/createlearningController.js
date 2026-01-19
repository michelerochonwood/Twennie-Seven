function canContributeFromUser(u) {
  if (!u) return false;

  if (u.groupLeaderEmail || u.membershipType === 'leader') return true;
  if (u.membershipType === 'group_member') return true;

  if (u.membershipType === 'member') {
    return u.accessLevel === 'paid_individual' || u.accessLevel === 'contributor_individual';
  }

  return false;
}

exports.getCreateLearningGuide = (req, res) => {
  res.render('promo_views/creating_content', {
    layout: 'mainlayout',
    canContribute: canContributeFromUser(req.user)
  });
};
