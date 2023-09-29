var express = require('express');
var router = express.Router();

const { isLoggedIn } = require('../middleware/route-guard')

router.get('/userProfile', (req, res) => {

res.render('users/user-profile.hbs', {user: req.session.user})

});

//assign user to session after user signs in

module.exports = router;
