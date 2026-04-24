module.exports = {
  requireLogin: (req, res, next) => {
    if (req.session && req.session.loggedIn) return next();
    res.redirect('/login');
  }
};
