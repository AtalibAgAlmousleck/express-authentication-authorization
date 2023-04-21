const express = require('express');

const db = require('../data/database');
const bcrypt = require('bcryptjs');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: ''
    };
  }

  req.session.inputData = null; // clear the seesion
  res.render('signup', { inputData: sessionInputData });
});

//! Create new user
router.post('/signup', async function (req, res) {
  const userData = req.body;
  const enterEmail = userData.email;
  const enterConfirmEmail = userData['confirm-email'];
  const enterPassword = userData.password;

  // User input validations
  if (!enterEmail || !enterConfirmEmail ||
      !enterPassword || enterPassword.trim() < 6 ||
      enterEmail !== enterConfirmEmail ||
      !enterEmail.includes('@')) {
    //! Stored data in to a session
    req.session.inputData = {
      hasError: true,
      message: 'Invalid input - please check your data.',
      email: enterEmail,
      confirmEmail: enterConfirmEmail,
      password: enterPassword
    };
    //console.log('Incorrect data');
    req.session.save(function() {
      return res.redirect('/signup');
    });
    return;
  }

  const existingUser = await db.getDb()
       .collection('users').findOne({ email: enterEmail });

  if (existingUser) {
    //console.log('User with the given email taken.');
    req.session.inputData = {
      hasError: true,
      message: 'User with the given email taken!',
      email: enterEmail,
      confirmEmail: enterConfirmEmail,
      password: enterPassword
    };
    // save the session
    req.session.save(function () {
      res.redirect('/signup');
    });
    return;
  }

  const encodedPassword = await bcrypt.hash(enterPassword, 12);

  const user = {
    email: enterEmail,
    password: encodedPassword
  };

  await db.getDb().collection('users').insertOne(user);
  res.redirect('/login');
});

router.get('/login', function (req, res) {

  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      password: ''
    };
  }

  req.session.inputData = null;
  res.render('login', { inputData: sessionInputData });
});

//! Users login
router.post('/login', async function (req, res) {
  const userData = req.body;
  const enterEmail = userData.email;
  const enterPassword = userData.password;

  // check if we do have a user
  const existingUser = await db.getDb()
     .collection('users').findOne({ email: enterEmail });

     if(!existingUser) {
      req.session.inputData = {
        hasError: true,
        message: 'Incorrect username or password.',
        email: enterEmail,
        password: enterPassword
      }
      req.session.save(function () {
        res.redirect('/login');
      });
      return;
     }

     // compare user encodedPassword
    const passwordAreEqual = await bcrypt.compare(enterPassword, existingUser.password);

    if (!passwordAreEqual) {
      req.session.inputData = {
        hasError: true,
        message: 'Incorrect username or password.',
        email: enterEmail,
        password: enterPassword
      }
      req.session.save(function () {
        res.redirect('/login');
      });
      return;
    }
    
    req.session.user = { id: existingUser._id, email: existingUser.email }
    req.session.isAuthenticated = true;
    req.session.save(function() {
      res.redirect('/profile');
    });
});

router.get('/admin', async function (req, res) {
  // Check if user is not authenticated
  if (!res.locals.isAuth) {
    return res.status(401).render('401');
  }

  //const user = await db.getDb().collection('users').findOne({_id: req.session.user.id});

  if (!res.locals.isAdmin) {
   return res.status(403).render('403');
  }
  res.render('admin');
});

router.get('/profile', function (req, res) {
  // Check if user is not authenticated
  if (!res.locals.isAuth) {
    return res.status(401).render('401');
  }
  res.render('profile');
});

router.post('/logout', function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/');
});

module.exports = router;
