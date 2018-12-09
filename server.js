
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
import * as secrets from "docker-secrets-nodejs";

const ovi_config = {
  server_port: getConfig("server_port", false, 8080),
  wsbase: getConfig("wsbase", false, 'http://localhost:8080'),
  ip_header: getConfig("client_ip_header", false, null),
  redis_host: getConfig("redis_host", false, 'localhost'),
  redis_port: getConfig("redis_port", false, 6379),
  session_secret: getConfig("session_secret", false, crypto.randomBytes(48).toString('hex')),
  jwt_pub_key: getConfig("jwt_pub_key", true, null),
  jwt_prv_key: getConfig("jwt_prv_key", true, null),
  jwt_iss: getConfig("jwt_iss", false, 'example.com'),
  jwt_token_test: getConfig("jwt_token_test", false, false),
  token_disclaimer: getConfig("token_disclaimer", true, null),
  DEBUG: getConfig("debug", false, false),
};

var public_key = fs.readFileSync(ovi_config.jwt_pub_key);
var private_key = fs.readFileSync(ovi_config.jwt_prv_key);

// verify public and private keys match
jwt.verify(jwt.sign({test: true}, private_key, {algorithm: 'RS256'}), public_key);

// standardize the various passport strategies

const passport_facebook = {
  clientID: getConfig("oauth_facebook_clientid", false, null),
  clientSecret: getConfig("oauth_facebook_secret", false, null),
  enableProof: true,
  state: true,
  profileFields: ['id', 'name', 'displayName', 'picture', 'emails'],
};

const passport_google = {
  clientID: getConfig("oauth_google_clientid", false, null),
  clientSecret: getConfig("oauth_google_secret", false, null),
  state: true,
};

const passport_dropbox = {
  clientID: getConfig("oauth_dropbox_clientid", false, null),
  clientSecret: getConfig("oauth_dropbox_secret", false, null),
  state: true,
  apiVersion: '2',
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

function getConfig(item, required, def) {
  let value = secrets.get(item);
  if (!value) {
    if (required) {
      let msg = "Missing config: "+item.toUpperCase();
      console.log(msg);
      throw msg;
    } else {
      return def;
    }
  }
  return value;
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
  req.user.device = req.session.device;
  var u = JSON.stringify(req.user);
  rc.lpush('jwt:'+req.user.id, u);
  wslog(req, 'oauthredir', {user_id: req.user.id, type: type});
  return u;
}

function moauthredir(req, res) {
  var u = oauthredir(req, res, 'mobile');
  //res.redirect('OurVoiceApp://login?jwt=' + jwt.sign(u, private_key, {algorithm: 'RS256'}));
  res.redirect('http://192.168.0.248:3000/jwt/' + jwt.sign(u, private_key, {algorithm: 'RS256'}));
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

function pubkey(req, res) {
  res.send(public_key);
}

function tokentest(req, res) {
  let id = Math.ceil(Math.random()*10000000);
  res.send({jwt: jwt.sign(JSON.stringify({
    id: 'test:' + id,
    name: "Test User "+id,
    iss: ovi_config.jwt_iss,
    iat: Math.floor(new Date().getTime() / 1000),
    exp: Math.floor(new Date().getTime() / 1000)+604800,
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

// always set the jwt iss header
app.use(function (req, res, next) {
  res.set('x-jwt-iss', ovi_config.jwt_iss);
  return next();
});

// internal routes
app.get('/poke', poke);

// Set up auth routes
app.post('/auth/jwt', issueJWT);
app.get('/auth/pubkey', pubkey);
// Register Dropbox Passport strategy

if (passport_facebook.clientID && passport_facebook.clientSecret) {
  passport.use(new FacebookStrategy(passport_facebook,
    async (accessToken, refreshToken, profile, done)
      => done(null, transformFacebookProfile(profile._json))
  ));
  app.get('/auth/fm', function(req, res, next) {
    req.session.device = req.query.device;
    passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', scope: ['email'] }
    )(req, res, next)});
  app.get('/auth/fm/callback', passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', failureRedirect: '/auth/fm' }), moauthredir);
}

if (passport_google.clientID && passport_google.clientSecret) {
  passport.use(new GoogleStrategy(passport_google,
    async (accessToken, refreshToken, profile, done)
      => done(null, transformGoogleProfile(profile._json))
  ));
  app.get('/auth/gm', function(req, res, next) {
    req.session.device = req.query.device;
    passport.authenticate('google', { loginHint: req.query.loginHint, callbackURL: ovi_config.wsbase+'/auth/gm/callback', scope: ['profile', 'email'] }
    )(req, res, next)});
  app.get('/auth/gm/callback', passport.authenticate('google',   { callbackURL: ovi_config.wsbase+'/auth/gm/callback', failureRedirect: '/auth/gm' }), moauthredir);
}

if (passport_dropbox.clientID && passport_dropbox.clientSecret) {
  passport.use(new DropboxOAuth2Strategy(passport_dropbox,
    function(accessToken, refreshToken, profile, done) {
      profile._json.accessToken = accessToken;
      return done(null, profile._json);
    }
  ));
  app.get('/auth/dm', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dm/callback' }));
  app.get('/auth/dm/callback', passport.authenticate('dropbox-oauth2', { callbackURL: ovi_config.wsbase+'/auth/dm/callback' }), dboxoauth);
}

if (ovi_config.jwt_token_test)
  app.get('/auth/tokentest', tokentest);

Object.keys(ovi_config).forEach((k) => {
  delete process.env[k.toUpperCase()];
});
require = null;

if (!ovi_config.DEBUG) {
  process.on('SIGUSR1', () => {
    //process.exit(1);
    throw "Caught SIGUSR1, exiting."
  });
}

// Launch the server
const server = app.listen(ovi_config.server_port, () => {
  const { address, port } = server.address();
  console.log('sm-oauth express');
  console.log(`Listening at http://${address}:${port}`);
});

