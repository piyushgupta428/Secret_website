//jshint esversion:6
// require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const dateFormat = require('dateformat');
dateFormat.masks.createdTime = 'dddd, mmmm dS, yyyy, h:MM:ss TT';
if (process.env.NODE_ENV !== 'production') {
  const dotenv = require('dotenv');
  dotenv.config();
}

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));


app.use(session({
  secret: process.env.SECRET || "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

var mconnect = '';
const mauth = process.env.MONGO_USER ? `${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@` : '';
const mhost = process.env.MONGO_HOST || 'localhost';
const mport = process.env.MONGO_PORT || 27017;
if (process.env.USE_ATLAS == 'true') {
mconnect = `mongodb://${mauth}${mhost}`;
} else {
mconnect = `mongodb://${mauth}${mhost}:${mport}/usersDB`;
};
mongoose.connect(mconnect, {
useNewUrlParser: true,
useUnifiedTopology: true
}).catch(err => {
console.log(`Mongoose connection error:\n${mconnect}\n${err}`);
});

// mongoose.connect("mongodb://localhost:27017/secretuserDB", {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  created_on: String,
  password: String,
  first_name: String,
  last_name: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CLIENT_HOST + 'auth/google/secrets',
     passReqToCallback: true
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(request, accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
  res.render("home");
});

app.get("/auth/google",
passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
passport.authenticate('google', { failureRedirect: "/login"}),
function(req, res){
  res.redirect('/secrets');
});


app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

// app.get("/secrets", function(req, res){
//   // if(req.isAuthenticated()){
//   //   res.render("secrets");
//   // } else{
//   //   res.redirect("/login");
//   // }
//   User.find({"secret": {$ne: null}}, function(err, foundUsers){
//     if(err){
//       console.log(err);
//     } else {
//       if (foundUsers){
//         res.render("secrets", {usersWithSecrets: foundUsers});
//       }
//     }
//   });
// });

app.get('/secrets', function(req, resp) {
if (req.isAuthenticated()) {
  User.find({
    secret: { $ne: null }
  }, function(err, foundUsers) {
    if (err) {
      console.log(`No secrets found:\n${err}`);
    }
    resp.render('secrets', { usersWithSecrets: foundUsers || [] });
  });
} else {
  resp.render('login', {
    errorMsg: 'You must be logged in to view the secret'
  });
}
});

app.route('/register')
  .get(function(req, resp) {
    resp.render('register', {
      errorMsg: false
    });
  })
  .post(function(req, resp) {
    User.register({
      username: req.body.username
    }, req.body.password, function(err, newUser) {
      if (err) {
        console.log(`REGISTER ERROR:\n${err}`);
        resp.render('register', {
          errorMsg: err
        });
      } else {
        passport.authenticate("local")(req, resp, function() {
          resp.redirect('/secrets');
        });
      }
    });
  });
app.route('/login')
  .get(function(req, resp) {
    resp.render('login', {
      errorMsg: false
    });
  })
  .post(function(req, resp) {
    const user = new User({
      username: req.body.username,
      password: req.body.MONGO_PASSWORD
    });
    req.login(user, function(err) {
      if (err) {
        console.log(`LOGIN ERROR:\n${err}`);
        resp.render('login', {
          errorMsg: err
        });
      } else {
        passport.authenticate("local", {
          failureRedirect: '/login',
          failureFlash: true
        })(req, resp, function() {
          resp.redirect('/secrets');
        });
      }
    });
  });
app.route('/logout')
  .get(function(req, resp) {
    req.logout();
    resp.redirect('/');
  });
app.route('/submit')
  .get(function(req, resp) {
    if (req.isAuthenticated()) {
      resp.render('submit');
    } else {
      resp.render('login', {
        errorMsg: 'You must be logged in to submit secrets'
      });
    }
  })
  .post(function(req, resp) {
    const submittedSecret = req.body.secret;
    console.log(req.user);
    User.findById(req.user.id, function(err, foundUser) {
      if (err) {
        console.log(`SUBMIT SECRET ERROR:\n${err}`);
        resp.render('login', {
          errorMsg: 'You must be logged in to submit secrets'
        });
      } else {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save(function(error){
            if (error) {
              console.log(`SECRET SAVE ERROR:\n${error}`);
              resp.redirect('/');
            } else {
              resp.redirect('/secrets');
            }
          });
        } else {
          resp.render('login', {
            errorMsg: 'You must be logged in to submit secrets'
          });
        }
      };
    });
  });

// app.get("/submit", function(req,res){
//   if(req.isAuthenticated()){
//     res.render("submit");
//   } else{
//     res.redirect("/login");
//   }
// });
//
// app.post("/submit", function(req,res){
//   const submittedSecret = req.body.secret;
//
//   User.findById(req.user.id, function(err, foundUser){
//     if(err){
//       console.log(err);
//     } else {
//       if(foundUser){
//         foundUser.secret = submittedSecret;
//         foundUser.save(function(){
//           res.redirect("/secrets");
//         });
//       }
//     }
//   });
// });


// app.get("/logout", function(req, res){
//   req.logout();
//   res.redirect("/");
// });
//
//
//
// app.post("/register", function(req,res){

// bcrypt.hash(req.body.password, saltRounds, function(err, hash){
//   const newUser = new User({
//     email: req.body.username,
//     password: hash
//   });
//
//   newUser.save(function(err){
//     if(err){
//       console.log(err);
//     } else {
//       res.render("secrets");
//     }
//   });
//
// });

// User.register({username: req.body.username}, req.body.password, function(err, user){
//   if(err){
//     console.log(err);
//     res.redirect("/register");
//   } else{
//     passport.authenticate("local")(req, res, function(){
//       res.redirect("/secrets");
//     });
//   }
// });
//
// });
//
// app.post("/login", function(req, res){
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username}, function(err, foundUser){
  //   if(err){
  //     console.log(err);
  //   }else{
  //     if(foundUser){
  //       // if(foundUser.password === password){
  //       bcrypt.compare(password, foundUser.password, function(err, result){
  //         if(result === true){
  //           res.render("secrets");
  //         }
  //       });
  //
  //       // }
  //     }
  //   }
  // });
// const user = new User({
//   username: req.body.username,
//   password: req.body.password
// });
//
// req.login(user, function(err){
//   if(err){
//     console.log(err);
//   } else {
//     passport.authenticate("local")(req, res, function(){
//       res.redirect("/secrets");
//     });
//   }
// })
// });




const port = process.env.PORT || 3000;
app.listen(port, function() {
console.log(`Express server listening on port ${port}`);
});
// app.listen(process.env.PORT || 3000, function(){
//   console.log("server started on port 3000.");
// });
