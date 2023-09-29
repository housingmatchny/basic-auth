var express = require('express');
var router = express.Router();
var mongoose = require('mongoose')

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User')

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard')

router.get('/signup',isLoggedOut, (req, res, next) => {
    res.render('auth/signup.hbs')
})
//when the request at /signup, we render the signup.hbs file.  
//Middleware occurs in the middle. if the user is logged out, then proceeds to rendering.

router.post('/signup', isLoggedOut, (req, res, next) => {
    // console.log("The form data: ", req.body);

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        res.render('auth/signup.hbs', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
        return;//return here is like a break; no need to return anything
    }

    // const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

    // if (!regex.test(password)) {
    //     res
    //         .status(500)
    //         .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    //     return;
    // }//if this does not pass the test, then we'll show a 500 error message and render the auth/signup page and error message

    bcryptjs
        .genSalt(saltRounds)
        .then(salt => bcryptjs.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                // username: username
                username,
                email,
                // passwordHash => this is the key from the User model
                //     ^
                //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
                passwordHash: hashedPassword
            });
        })
        .then(userFromDB => {
            console.log('Newly created user is: ', userFromDB);
            res.redirect('/auth/login')//send to login page after signing up
        })
        .catch((error) => {
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup.hbs', { errorMessage: error.message });
            } else if (error.code === 11000) {

                console.log(" Username and email need to be unique. Either username or email is already used. ");

                res.status(500).render('auth/signup', {
                    errorMessage: 'Invalid username, email or password.'//tip: try to be ague in error messaging, like this one
                });
            } else {
                next(error);
            }
        });
})

router.get('/login', isLoggedOut, (req, res, next) => {
    res.render('auth/login.hbs')
})

router.post('/login', (req, res, next) => {
    console.log('SESSION =====> ', req.session);
    const { email, password } = req.body;
   
    if (email === '' || password === '') {
      res.render('auth/login', {
        errorMessage: 'Please enter both, email and password to login.'
      });
      return;
    }
   
    User.findOne({ email })
      .then(user => {
        if (!user) {
          console.log("Email not registered. ");
          res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
          return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) {
            req.session.user = user
            console.log("Session after success ==>", req.session)

            res.redirect('/users/userProfile')

        } else {
          console.log("Incorrect password. ");
          res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
        }
      })
      .catch(error => next(error));
  });

  router.post('/logout', isLoggedIn, (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');//redirects back to home after you logout; when you click logout again, it goes through the middleware and redirects you to login
    });
  });

module.exports = router;

// we have to export as a router for the router to work
// the router is an instantiation of the express router
