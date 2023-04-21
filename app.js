const path = require('path');

const express = require('express');
const session = require('express-session');
const mongodbStore = require('connect-mongodb-session');

const db = require('./data/database');
const demoRoutes = require('./routes/demo');

const MongoDBStore = mongodbStore(session);

const app = express();

const sessionStore = MongoDBStore({
  uri: 'mongodb://127.0.0.1:27017',
  databaseName: 'auth-demo',
  collection: 'sessions'
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: 'super-secret',
  resave: false, // only saved in database
  saveUninitialized: false, // only saved when we have some data on it
  store: sessionStore // where the data session should be stored
}));

// auth
app.use(async function(req, res, next) {
  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;
  //res.locals.isAuth = isAuth;

  if(!user || !isAuth) {
    return next();
  }

  const userDoc = await db.getDb().collection('users').findOne({ _id: user.id });
  const isAdmin = userDoc.isAdmin;

  res.locals.isAuth = isAuth;
  res.locals.isAdmin = isAdmin;

  next();
});

app.use(demoRoutes);

app.use(function(error, req, res, next) {
  res.render('500');
})

db.connectToDatabase().then(function () {
  app.listen(8080);
});
