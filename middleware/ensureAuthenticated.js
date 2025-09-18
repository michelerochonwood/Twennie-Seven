const ensureAuthenticated = (req, res, next) => {
    console.log('🔍 Middleware: Checking Authentication');
    console.log('   Session:', req.session);
    console.log('   req.isAuthenticated():', req.isAuthenticated && req.isAuthenticated());
    console.log('   req.user:', req.user);

    if (!req.user || !req.user._id) {
  console.warn('⚠️ req.user is missing or malformed. This will block access.');
}

    // ✅ Restore req.user early if missing but session has it
    if (!req.user && req.session.passport && req.session.passport.user) {
        console.warn("⚠️ Restoring user from session...");
        req.user = req.session.passport.user;
    }

    // ✅ Proceed if user is now valid
    if (req.user && req.user._id) {
        console.log('✅ Authenticated user:', {
            id: req.user._id,
            membershipType: req.user.membershipType || 'Unknown Type',
        });

        // ✅ Ensure session user is also present
        if (!req.session.user) {
            console.warn("⚠️ Session user data is missing, restoring session...");
            req.session.user = { 
                id: req.user._id, 
                username: req.user.username, 
                membershipType: req.user.membershipType 
            };
        }

        return next();
    }

    // 🚨 Authentication failed
    console.warn('🚨 Access Denied: Not Authenticated or missing req.user._id.');
    res.redirect('/auth/login');
};

module.exports = ensureAuthenticated;






