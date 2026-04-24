const express = require('express');
const router = express.Router();
const auth = require('../controllers/authController');
const { requireLogin } = require('../middleware/auth');

router.get('/', (req, res) => res.redirect('/login'));
router.get('/register', auth.getRegister);
router.post('/register', auth.postRegister);
router.get('/login', auth.getLogin);
router.post('/login', auth.postLogin);
router.get('/logout', auth.logout);
router.get('/dashboard', requireLogin, auth.getDashboard);

module.exports = router;
