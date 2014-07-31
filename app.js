var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var passport = require('passport');
var session = require('express-session')
var flash = require('connect-flash');
var Q = require('q')
var request = Q.denodeify(require('request'))
var LocalStrategy = require('passport-local').Strategy;
var OAuth = require('oauth').OAuth;
var app = express();
var config = require('./config')

var API_URL = process.env.API_URL || config.API_URL

console.log(API_URL)

var oa = new OAuth(
    "https://api.twitter.com/oauth/request_token",
    "https://api.twitter.com/oauth/access_token",
    process.env.TWITTER_API_KEY || config.TWITTER_API_KEY,
    process.env.TWITTER_API_SECRET || config.TWITTER_API_SECRET,
    "1.0",
    process.env.TWITTER_CALLBACK_URL || config.TWITTER_CALLBACK_URL,
    "HMAC-SHA1"
);

// var routes = require('./routes/index')
// var users = require('./routes/users');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({secret: process.env.SESSION_SECRET || config.SESSION_SECRET}))
app.use(passport.initialize());
app.use(passport.session());
app.use(flash())


app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


passport.serializeUser(function(user, done){
    done(null, parseInt(user.id))
})

passport.deserializeUser(function(id, done){

    var response = request(API_URL + '/user/' + id)

    response.then(function(res){
        console.log(res[1])
        done(null, JSON.parse(res[1]))
    })
   

})

passport.use('local-login', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true}, function(req, username, passwrod, done){

    var result;

    var options = {
        url: API_URL + '/user/verify',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: passwrod
        })
    }

    var callback = function(error, response, body){
        if (!error && response.statusCode == 200) {
            var info = JSON.parse(body)

            return info
        }
    }

    var response = request(options, callback)

    response.then(function(res){
        result = JSON.parse(res[0].body)
        // console.log(result.verify)

        if(result.verify == "fail"){
            return done(null, false, req.flash('loginMessage', 'Wrong password'))
        }

        return done(null, result.user)
    })    }))



require('./routes/routes.js')(app, passport)




module.exports = app;