var config = require('../config');
var request = require('request')
var OAuth = require('oauth').OAuth;
var Q = require('q');
var qs = require('querystring');
var Fitbit = require('fitbit')

var API_URL = process.env.API_URL || config.API_URL

var twitter_key = process.env.TWITTER_API_KEY || config.TWITTER_API_KEY
var twitter_secret = process.env.TWITTER_API_SECRET || config.TWITTER_API_SECRET
var twitter_callback = process.env.TWITTER_CALLBACK_URL || config.TWITTER_CALLBACK_UR

var twitter = new OAuth(
    "https://api.twitter.com/oauth/request_token",
    "https://api.twitter.com/oauth/access_token",
    twitter_key,
    twitter_secret,
    "1.0",
    twitter_callback,
    "HMAC-SHA1"
);

var fitbit_key = process.env.FITBIT_API_KEY || config.FITBIT_API_KEY
var fitbit_secret = process.env.FITBIT_API_SECRET || config.FITBIT_API_SECRET
var fitbit = new Fitbit(fitbit_key, fitbit_secret)

module.exports = function(app, passport) {

	app.get('/', function(req, res) {
		res.render('index.jade'); // load the index.jade file
	});


	app.get('/login', function(req, res) {
		res.render('login.jade', { message: req.flash('loginMessage') }); 
	});


	app.post('/login', passport.authenticate('local-login', {
		successRedirect : '/profile', // redirect to the secure profile section
		failureRedirect : '/login', // redirect back to the signup page if there is an error
		failureFlash : true // allow flash messages
	}));


	app.get('/signup', function(req, res) {
		res.render('signup.jade', { message: req.flash('signupMessage') });
	});

	// process the signup form
	// app.post('/signup', do all our passport stuff here);

	// =====================================
	// PROFILE SECTION =====================
	// =====================================
	// we will want this protected so you have to be logged in to visit
	// we will use route middleware to verify this (the isLoggedIn function)
	app.get('/profile', isLoggedIn, function(req, res) {
		res.render('profile.jade', {
			user : req.user.user, // get the user out of session and pass to template
			arks : req.user.arks // get the user out of session and pass to template
		});
	});

	app.get('/ark/delete/:id',isLoggedIn, function(req, res){
		response = request(API_URL + '/ark/delete/' + req.params.id, function(error, response, body){
			res.redirect('/profile')
		})
	})

	app.post('/ark/modify/:id',isLoggedIn, function(req, res){
		var options = {
	        url: API_URL + '/ark/modify/' + req.params.id,
	        method: 'POST',
	        headers: {
	            'Content-Type': 'application/json'
	        },
	        
	        body: JSON.stringify({
	            content: req.body.content
	        })
	    }

	    var callback = function(error, response, body){
	        if (!error && response.statusCode == 200) {
	            res.redirect('/profile')
	        }
	    }

	    request(options, callback)
	})

	app.post('/ark/create',isLoggedIn, function(req, res){
		var options = {
	        url: API_URL + '/ark/create',
	        method: 'POST',
	        headers: {
	            'Content-Type': 'application/json'
	        },
	        
	        body: JSON.stringify({
	            username: 'tiotao',
	            content: req.body.content
	        })
	    }

	    var callback = function(error, response, body){
	        if (!error && response.statusCode == 200) {
	            res.redirect('/profile')
	        }
	    }

	    request(options, callback)
	})


	app.get('/logout', function(req, res) {
		req.logout();
		res.redirect('/');
	});

	//Twitter and Fitbit

	app.get('/auth/twitter', function(req, res){
	    twitter.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, results){
	        if (error) {
	            console.log(error);
	            res.send("yeah no. didn't work.")
	        }
	        else {
	            req.session.oauth = {};
	            req.session.oauth.token = oauth_token;
	            req.session.oauth.token_secret = oauth_token_secret;
	            res.redirect('https://twitter.com/oauth/authenticate?oauth_token='+oauth_token)

	    }
	    });
	});

	app.get('/auth/twitter/callback', function(req, res, next){
	    if (req.session.oauth) {
	        req.session.oauth.verifier = req.query.oauth_verifier;
	        var oauth = req.session.oauth;

	        twitter.getOAuthAccessToken(oauth.token,oauth.token_secret,oauth.verifier, 
	        function(error, oauth_access_token, oauth_access_token_secret, results){
	            if (error){
	                console.log(error);
	                res.send("yeah something broke.");
	            } else {
	                req.session.oauth.access_token = oauth_access_token;
	                req.session.oauth,access_token_secret = oauth_access_token_secret;
	                var options = {
	                    url: API_URL + '/user/connect-twitter',
	                    method: 'POST',
	                    headers: {
	                        'Content-Type': 'application/json'
	                    },
	                    
	                    body: JSON.stringify({
	                        id: req.session.passport.user,
	                        twitter_id: results.user_id,
	                        twitter_token: oauth_access_token,
	                        twitter_secret: oauth_access_token_secret
	                    })
	                }

	                var callback = function(error, response, body){
	                    if (!error && response.statusCode == 200) {
	                        res.redirect('/profile')
	                    }
	                }
	                
	                request(options, callback)

	            }
	        }
	        );
	    } else
	        next(new Error("you're not supposed to be here."))
	});

	app.get('/auth/fitbit', function(req, res){
		
		fitbit.getRequestToken(function(err, token, tokenSecret){
			if (err) {
				console.log(err)
				return;
			}

			req.session.oauth = {
				requestToken: token, 
				requestTokenSecret: tokenSecret
			}

			res.redirect(fitbit.authorizeUrl(token))
		})
	})

	app.get('/auth/fitbit/callback', function(req, res){
		var verifier = req.query.oauth_verifier, 
			oauthSettings = req.session.oauth
				
		fitbit.getAccessToken(
			oauthSettings.requestToken,
			oauthSettings.requestTokenSecret,
			verifier,
			
			function(err, token, secret){

				if (err) {
					return ;
				}

				oauthSettings.accessToken = token
				oauthSettings.accessTokenSecret = secret

				var options = {
                    url: API_URL + '/user/connect-fitbit',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    
                    body: JSON.stringify({
                        id: req.session.passport.user,
                        fitbit_id: 'N/A',
                        fitbit_token: token,
                        fitbit_secret: secret
                    })
                }

                var callback = function(error, response, body){
                    if (!error && response.statusCode == 200) {
                        // console.log(body)
                        res.redirect('/profile')
                    }
                }
                
                request(options, callback)
			})
	})


};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {

	// if user is authenticated in the session, carry on 
	if (req.isAuthenticated())
		return next();

	// if they aren't redirect them to the home page
	res.redirect('/');
}
