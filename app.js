//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("express")
const mongoose = require ("mongoose");
// const bcrypt = require('bcrypt')
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');;
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const LocalStrategy = require("passport-local").Strategy;
const app = express();
const findOrCreate = require('mongoose-findorcreate')

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}))
app.use(bodyParser.json());

app.use(session({
    secret: "I Love y'all hoes",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());

app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new LocalStrategy(
    function(username, password, done) {
      User.findOne({ username: username }, function (err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        if (!user.verifyPassword(password)) { return done(null, false); }
        return done(null, user);
      });
    }
  ));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({facebookID: profile.id}, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));


mongoose.connect("mongodb://localhost:27017/userDB", {useUnifiedTopology: true, useNewUrlParser: true});
mongoose.set("useCreateIndex", true)

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookID: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

app.route('/')
    .get((req, res) => {
        res.render("home")
    })


app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });
  
app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { successRedirect: '/secrets',failureRedirect: '/' }));
    

app.route('/users')
    .get((req, res) => {
        User.find({}, (err, users)=>{
            console.log(users)
        })
})


app.route('/login')
    .get((req,res) => {
        res.render("login")
    })

app.post('/login', 
    passport.authenticate('local', { failureRedirect: '/login' }),
    function(req, res) {
      res.redirect('/secrets');
    });

app.route("/secrets")
    .get((req, res) => {
        User.find({"secret": {$ne: null}}, (err, users) => {
            if (err){
                console.log(err, "Couldn't access secrets")
            } else {
                if (users) {
                    res.render("secrets", {usersWithSecrets: users});
                }
            }
        })
    });

app.route("/register")
    .get((req, res) => {
        res.render("register")
    })

    .post((req, res) => {
        // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        //     if (err){
        //         console.log(err, "An error occured while trying to register new user")
        //     } else {
        //         const newUser = new User({
        //             email: req.body.username,
        //             password: hash
        //         })
        
        //         newUser.save(err=> {
        //             if (err) {
        //                 console.log(err)
        //             } else {
        //                 res.render("secrets")
        //             }
        //         })
        //     }
        // });   

        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if (err) {
                console.log(err,`Experienced error creating user`)
                res.redirect("/register")
             } else {
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets")
                });
             }
          });
          
    })

    app.route("/logout")
        .get((req,res) => {
            req.logout();
            res.redirect("/")
        })
    
    app.route("/submit")
        .get((req,res) => {
            if (req.isAuthenticated()){
                res.render("submit")
            } else {
                res.redirect("/login")
            }
        })
        .post((req, res) => {
            const submittedSecret = req.body.secret;

            User.findById(req.user.id, (err, user) => {
                if (err) {
                    console.log(err, "Experienced error uploading secret")
                } else  {
                    if (user){
                        user.secret = submittedSecret;
                        user.save(() => {
                            res.redirect("/secrets")
                        });
                    }
                }
            })
        })

app.listen(3000, () => {
    console.log(`Listenting on port 3000`)
});