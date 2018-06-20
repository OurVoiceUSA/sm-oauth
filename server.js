
import express from 'express';
import expressLogging from 'express-logging';
import expressSession from 'express-session';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import logger from 'logops';
import redis from 'redis';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import passport from 'passport';
import FacebookStrategy from 'passport-facebook';
import GoogleStrategy from 'passport-google-oauth20';
import DropboxOAuth2Strategy from 'passport-dropbox-oauth2';

const ovi_config = {
  server_port: ( process.env.SERVER_PORT ? process.env.SERVER_PORT : 8080 ),
  wsbase: ( process.env.WSBASE ? process.env.WSBASE : 'http://localhost:8080' ),
  ip_header: ( process.env.CLIENT_IP_HEADER ? process.env.CLIENT_IP_HEADER : null ),
  redis_host: ( process.env.REDIS_HOST ? process.env.REDIS_HOST : 'localhost' ),
  redis_port: ( process.env.REDIS_PORT ? process.env.REDIS_PORT : 6379 ),
  session_secret: ( process.env.SESSION_SECRET ? process.env.SESSION_SECRET : crypto.randomBytes(48).toString('hex') ),
  jwt_prv_key: ( process.env.JWT_PRV_KEY ? process.env.JWT_PRV_KEY : missingConfig("JWT_PRV_KEY") ),
  jwt_iss: ( process.env.JWT_ISS ? process.env.JWT_ISS : 'example.com' ),
  token_disclaimer: ( process.env.TOKEN_DISCLAIMER ? process.env.TOKEN_DISCLAIMER : missingConfig("TOKEN_DISCLAIMER") ),
  DEBUG: ( process.env.DEBUG ? true : false ),
};

var private_key = fs.readFileSync(ovi_config.jwt_prv_key);

const passport_facebook = {
  clientID: ( process.env.OAUTH_FACEBOOK_CLIENTID ? process.env.OAUTH_FACEBOOK_CLIENTID : missingConfig("OAUTH_FACEBOOK_CLIENTID") ),
  clientSecret: ( process.env.OAUTH_FACEBOOK_SECRET ? process.env.OAUTH_FACEBOOK_SECRET : missingConfig("OAUTH_FACEBOOK_SECRET") ),
  enableProof: true,
  state: true,
  profileFields: ['id', 'name', 'displayName', 'picture', 'emails'],
};

const passport_google = {
  clientID: ( process.env.OAUTH_GOOGLE_CLIENTID ? process.env.OAUTH_GOOGLE_CLIENTID : missingConfig("OAUTH_GOOGLE_CLIENTID") ),
  clientSecret: ( process.env.OAUTH_GOOGLE_SECRET ? process.env.OAUTH_GOOGLE_SECRET : missingConfig("OAUTH_GOOGLE_SECRET") ),
  state: true,
};

const passport_dropbox = {
  apiVersion: '2',
  clientID: ( process.env.OAUTH_DROPBOX_CLIENTID ? process.env.OAUTH_DROPBOX_CLIENTID : missingConfig("OAUTH_DROPBOX_CLIENTID") ),
  clientSecret: ( process.env.OAUTH_DROPBOX_SECRET ? process.env.OAUTH_DROPBOX_SECRET : missingConfig("OAUTH_DROPBOX_SECRET") ),
  state: true,
};

// Transform Facebook profile because Facebook and Google profile objects look different
// and we want to transform them into user objects that have the same set of attributes
const transformFacebookProfile = (profile) => ({
  id: 'facebook:' + profile.id,
  name: profile.name,
  email: (profile.email?profile.email:''),
  avatar: (profile.picture.data.url?profile.picture.data.url:''),
  iss: ovi_config.jwt_iss,
  iat: Math.floor(new Date().getTime() / 1000),
  exp: Math.floor(new Date().getTime() / 1000)+604800,
  disclaimer: ovi_config.token_disclaimer,
});

// Transform Google profile into user object
const transformGoogleProfile = (profile) => ({
  id: 'google:' + profile.id,
  name: profile.displayName,
  email: (profile.emails[0].value?profile.emails[0].value:''),
  avatar: (profile.image.url?profile.image.url:''),
  iss: ovi_config.jwt_iss,
  iat: Math.floor(new Date().getTime() / 1000),
  exp: Math.floor(new Date().getTime() / 1000)+604800,
  disclaimer: ovi_config.token_disclaimer,
});

// Register Facebook Passport strategy
passport.use(new FacebookStrategy(passport_facebook,
  async (accessToken, refreshToken, profile, done)
    => done(null, transformFacebookProfile(profile._json))
));

// Register Google Passport strategy
passport.use(new GoogleStrategy(passport_google,
  async (accessToken, refreshToken, profile, done)
    => done(null, transformGoogleProfile(profile._json))
));

// Register Dropbox Passport strategy
passport.use(new DropboxOAuth2Strategy(passport_dropbox,
  function(accessToken, refreshToken, profile, done) {
    // pass the accessToken along with the user object
    profile._json.accessToken = accessToken;
    return done(null, profile._json);
  }
));

// Serialize user into the sessions
passport.serializeUser((user, done) => done(null, user));

// Deserialize user from the sessions
passport.deserializeUser((user, done) => done(null, user));

// redis connection
var rc = redis.createClient(ovi_config.redis_port, ovi_config.redis_host,
  {
    // endlessly retry the database connection
    retry_strategy: function (options) {
      console.log('redis connection failed to "'+ovi_config.redis_host+'", retrying: this is attempt # '+options.attempt);
      return Math.min(options.attempt * 100, 3000);
    }
  }
);

rc.on('connect', async function() {
    console.log('Connected to redis at host "'+ovi_config.redis_host+'"');
});

function missingConfig(item) {
  let msg = "Missing config: "+item;
  console.log(msg);
  throw msg;
}

function getClientIP(req) {
  if (ovi_config.ip_header) return req.header(ovi_config.ip_header);
  else return req.connection.remoteAddress;
}

function wslog(req, ws, log) {
  log['client_ip'] = getClientIP(req);
  log['time'] = (new Date).getTime();
  let str = JSON.stringify(log);
  if (ovi_config.DEBUG) console.log('DEBUG: '+ws+': '+str);
  try {
    rc.lpush('wslog:'+ws, str);
  } catch (error) {
    console.log(error);
  }
}

// Redirect user back to the mobile app using Linking with a custom protocol OAuthLogin
function oauthredir(req, res, type) {
  req.user.sub = req.user.id; // the jwt "subject" is the userid
  var u = JSON.stringify(req.user);
  rc.lpush('jwt:'+req.user.id, u);
  wslog(req, 'oauthredir', {user_id: req.user.id, type: type});
  return u;
}

function moauthredir(req, res) {
  var u = oauthredir(req, res, 'mobile');
  res.redirect('OurVoiceApp://login?jwt=' + jwt.sign(u, private_key, {algorithm: 'RS256'}));
}

function dboxoauth(req, res) {
  res.redirect('OurVoiceApp://login?dropbox=' + jwt.sign(req.user, private_key, {algorithm: 'RS256'}));
}

/*
function dboxweboauth(req, res) {
  res.redirect(req.session.returnTo + '?dropbox=' + jwt.sign(req.user, private_key, {algorithm: 'RS256'}));
}
*/

function issueJWT(req, res) {
  if (!req.body.apiKey) return res.sendStatus(401);
  if (req.body.apiKey.length < 8 || req.body.apiKey.length > 64) return res.sendStatus(400);
  if (!req.body.apiKey.match(/^[a-zA-Z0-9\-]+$/)) return res.sendStatus(400);
  wslog(req, 'jwt', {apiKey: req.body.apiKey});
  res.send({jwt: jwt.sign(JSON.stringify({
    sub: req.body.apiKey,
    iss: ovi_config.jwt_iss,
    iat: Math.floor(new Date().getTime() / 1000),
    exp: Math.floor(new Date().getTime() / 1000)+60,
    disclaimer: ovi_config.token_disclaimer,
  }), private_key, {algorithm: 'RS256'})});
}

function poke(req, res) {
  if (rc.connected)
    return res.sendStatus(200);
  return res.sendStatus(500);
}

// Initialize http server
var connectRedis = require('connect-redis')(expressSession);
const app = express();
app.disable('x-powered-by');
app.use(expressLogging(logger));
app.use(expressSession({
    store: new connectRedis({client: rc}),
    secret: ovi_config.session_secret,
    saveUninitialized: false,
    resave: false
}));
app.use(bodyParser.json());
app.use(cors());

// Initialize Passport
app.use(passport.initialize());

// require ip_header if config for it is set
if (!ovi_config.DEBUG && ovi_config.ip_header) {
  app.use(function (req, res, next) {
    if (!req.header(ovi_config.ip_header)) {
      console.log('Connection without '+ovi_config.ip_header+' header');
      res.status(400).send();
    }
    else next();
  });
}

// store return URL in session
app.use(function (req, res, next) {
  return next();
});

// internal routes
app.get('/poke', poke);

// Set up auth routes
app.post('/auth/jwt', issueJWT);
app.get('/auth/dm', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dm/callback' }));
app.get('/auth/dw', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dw/callback' }));
app.get('/auth/fm', passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', scope: ['email']} ));
// google accepts the custom loginHint
app.get('/auth/gm', function(req, res, next) {
  passport.authenticate('google', { loginHint: req.query.loginHint, callbackURL: ovi_config.wsbase+'/auth/gm/callback', scope: ['profile', 'email'] }
  )(req, res, next)});
app.get('/auth/dm/callback', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dm/callback' }), dboxoauth);
//app.get('/auth/dw/callback', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dw/callback' }), dboxweboauth);
app.get('/auth/fm/callback', passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', failureRedirect: '/auth/fm' }), moauthredir);
app.get('/auth/gm/callback', passport.authenticate('google',   { callbackURL: ovi_config.wsbase+'/auth/gm/callback', failureRedirect: '/auth/gm' }), moauthredir);

// Launch the server
const server = app.listen(ovi_config.server_port, () => {
  const { address, port } = server.address();
  console.log('sm-oauth express');
  console.log(`Listening at http://${address}:${port}`);
});

