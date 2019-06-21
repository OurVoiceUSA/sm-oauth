
import express from 'express';
import expressLogging from 'express-logging';
import expressSession from 'express-session';
import cors from 'cors';
import fs from 'fs';
import logger from 'logops';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import passport from 'passport';
import Auth0Strategy from 'passport-auth0';
import FacebookStrategy from 'passport-facebook';
import GoogleStrategy from 'passport-google-oauth20';
import DropboxOAuth2Strategy from 'passport-dropbox-oauth2';
import { getConfig } from 'ourvoiceusa-sdk-js';

import { ov_config } from './ov_config';

var public_key = fs.readFileSync(ov_config.jwt_pub_key);
var private_key = fs.readFileSync(ov_config.jwt_prv_key);

// verify public and private keys match
jwt.verify(jwt.sign({test: true}, private_key, {algorithm: 'RS256'}), public_key);

// standardize the various passport strategies

const passport_auth0 = {
   domain: getConfig("oauth_auth0_domain", false, null),
   clientID: getConfig("oauth_auth0_clientid", false, null),
   clientSecret: getConfig("oauth_auth0_secret", false, null),
   callbackURL: ov_config.wsbase+'/auth/auth0/callback',
};

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

// auth0 transformation
const transformAuth0Profile = (profile) => ({
  id: 'auth0:' + profile.sub,
  name: profile.name,
  email: profile.email,
  avatar: profile.picture,
  iss: ov_config.jwt_iss,
  iat: Math.floor(new Date().getTime() / 1000),
  exp: Math.floor(new Date().getTime() / 1000)+604800,
  disclaimer: ov_config.token_disclaimer,
});

// Transform Facebook profile because Facebook and Google profile objects look different
// and we want to transform them into user objects that have the same set of attributes
const transformFacebookProfile = (profile) => ({
  id: 'facebook:' + profile.id,
  name: profile.name,
  email: (profile.email?profile.email:''),
  avatar: (profile.picture.data.url?profile.picture.data.url:''),
  iss: ov_config.jwt_iss,
  iat: Math.floor(new Date().getTime() / 1000),
  exp: Math.floor(new Date().getTime() / 1000)+604800,
  disclaimer: ov_config.token_disclaimer,
});

// Transform Google profile into user object
const transformGoogleProfile = (profile) => ({
  id: 'google:' + profile.sub,
  name: profile.name,
  email: profile.email,
  avatar: profile.picture,
  iss: ov_config.jwt_iss,
  iat: Math.floor(new Date().getTime() / 1000),
  exp: Math.floor(new Date().getTime() / 1000)+604800,
  disclaimer: ov_config.token_disclaimer,
});

// Serialize user into the sessions
passport.serializeUser((user, done) => done(null, user));

// Deserialize user from the sessions
passport.deserializeUser((user, done) => done(null, user));

function getClientIP(req) {
  if (ov_config.ip_header) return req.header(ov_config.ip_header);
  else return req.connection.remoteAddress;
}

function wslog(req, ws, log) {
  log['client_ip'] = getClientIP(req);
  log['time'] = (new Date).getTime();
  let str = JSON.stringify(log);
  if (ov_config.DEBUG) console.log('DEBUG: '+ws+': '+str);
  try {
    req.app.rc.lpush('wslog:'+ws, str);
  } catch (error) {
    console.log(error);
  }
}

// Redirect user back to the mobile app using Linking with a custom protocol OAuthLogin
function oauthredir(req, res, type) {
  req.user.sub = req.user.id; // the jwt "subject" is the userid
  req.user.device = req.session.device;
  var u = JSON.stringify(req.user);
  req.app.rc.lpush('jwt:'+req.user.id, u);
  wslog(req, 'oauthredir', {user_id: req.user.id, type: type});
  return u;
}

function moauthredir(req, res) {
  let context;
  let redir = ov_config.wabase;
  if (req.session.app) {
    context = 'web';
    if (req.session.local) redir = 'http://localhost:3000';
    redir += '/'+req.session.app+'/#/jwt/';
  } else {
    context = 'mobile';
    redir = 'OurVoiceApp://login?jwt=';
  }
  var u = oauthredir(req, res, context);
  res.redirect(redir + jwt.sign(u, private_key, {algorithm: 'RS256'}));
}

function dboxoauth(req, res) {
  res.redirect('OurVoiceApp://login?dropbox=' + jwt.sign(req.user, private_key, {algorithm: 'RS256'}));
}

function issueJWT(req, res) {
  if (!req.body.apiKey) return res.sendStatus(401);
  if (req.body.apiKey.length < 8 || req.body.apiKey.length > 64) return res.sendStatus(400);
  if (!req.body.apiKey.match(/^[a-zA-Z0-9\-]+$/)) return res.sendStatus(400);
  wslog(req, 'jwt', {apiKey: req.body.apiKey});
  res.send({jwt: jwt.sign(JSON.stringify({
    sub: req.body.apiKey,
    iss: ov_config.jwt_iss,
    iat: Math.floor(new Date().getTime() / 1000),
    exp: Math.floor(new Date().getTime() / 1000)+60,
    disclaimer: ov_config.token_disclaimer,
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
    iss: ov_config.jwt_iss,
    iat: Math.floor(new Date().getTime() / 1000),
    exp: Math.floor(new Date().getTime() / 1000)+604800,
    disclaimer: ov_config.token_disclaimer,
  }), private_key, {algorithm: 'RS256'})});
}

function poke(req, res) {
  if (req.app.rc.connected)
    return res.sendStatus(200);
  return res.sendStatus(500);
}

export function doExpressInit(log, redis) {
  // Initialize http server
  var app = express();
  if (log) app.use(expressLogging(logger));
  app.disable('x-powered-by');
  var connectRedis = require('connect-redis')(expressSession);

  // redis connection
  app.rc = redis.createClient(ov_config.redis_port, ov_config.redis_host,
    {
      // endlessly retry the database connection
      retry_strategy: function (options) {
        console.log('redis connection failed to "'+ov_config.redis_host+'", retrying: this is attempt # '+options.attempt);
        return Math.min(options.attempt * 100, 3000);
      }
    }
  );

  app.rc.on('connect', async function() {
      console.log('Connected to redis at host "'+ov_config.redis_host+'"');
  });

  app.use(expressSession({
      store: new connectRedis({client: app.rc}),
      secret: ov_config.session_secret,
      saveUninitialized: false,
      resave: false
  }));

  app.use(bodyParser.json());
  app.use(cors());
  app.use(helmet());

  // Initialize Passport
  app.use(passport.initialize());

  // require ip_header if config for it is set
  if (!ov_config.DEBUG && ov_config.ip_header) {
    app.use(function (req, res, next) {
      if (!req.header(ov_config.ip_header)) {
        console.log('Connection without '+ov_config.ip_header+' header');
        res.status(400).send();
      }
      else next();
    });
  }

  // always set the jwt iss header
  app.use(function (req, res, next) {
    res.set('x-jwt-iss', ov_config.jwt_iss);
    if (req.query.app) req.session.app = req.query.app;
    if (req.query.local) req.session.local = req.query.local;
    return next();
  });

  // internal routes
  app.get('/poke', poke);

  // Set up auth routes
  app.post('/auth/jwt', issueJWT);
  app.get('/auth/pubkey', pubkey);
  // Register Dropbox Passport strategy

  if (passport_auth0.clientID && passport_auth0.clientSecret && passport_auth0.domain) {
    passport.use(new Auth0Strategy(passport_auth0,
      async (accessToken, refreshToken, profile, done) => done(null, transformAuth0Profile(profile._json))
    ));
    app.get('/auth/auth0', function(req, res, next) {
      req.session.device = req.query.device;
      passport.authenticate('auth0', { callbackURL: ov_config.wsbase+'/auth/auth0/callback' }
      )(req, res, next)});
    app.get('/auth/auth0/callback', passport.authenticate('auth0', { failureRedirect: '/auth/auth0' }), moauthredir);
  }

  if (passport_facebook.clientID && passport_facebook.clientSecret) {
    passport.use(new FacebookStrategy(passport_facebook,
      async (accessToken, refreshToken, profile, done) => done(null, transformFacebookProfile(profile._json))
    ));
    app.get('/auth/fm', function(req, res, next) {
      req.session.device = req.query.device;
      passport.authenticate('facebook', { callbackURL: ov_config.wsbase+'/auth/fm/callback', scope: ['email'] }
      )(req, res, next)});
    app.get('/auth/fm/callback', passport.authenticate('facebook', { callbackURL: ov_config.wsbase+'/auth/fm/callback', failureRedirect: '/auth/fm' }), moauthredir);
  }

  if (passport_google.clientID && passport_google.clientSecret) {
    passport.use(new GoogleStrategy(passport_google,
      async (accessToken, refreshToken, profile, done) => done(null, transformGoogleProfile(profile._json))
    ));
    app.get('/auth/gm', function(req, res, next) {
      req.session.device = req.query.device;
      passport.authenticate('google', { loginHint: req.query.loginHint, callbackURL: ov_config.wsbase+'/auth/gm/callback', scope: ['profile', 'email'] }
      )(req, res, next)});
    app.get('/auth/gm/callback', passport.authenticate('google',   { callbackURL: ov_config.wsbase+'/auth/gm/callback', failureRedirect: '/auth/gm' }), moauthredir);
  }

  if (passport_dropbox.clientID && passport_dropbox.clientSecret) {
    passport.use(new DropboxOAuth2Strategy(passport_dropbox,
      function(accessToken, refreshToken, profile, done) {
        profile._json.accessToken = accessToken;
        return done(null, profile._json);
      }
    ));
    app.get('/auth/dm', passport.authenticate('dropbox-oauth2', { callbackURL: ov_config.wsbase+'/auth/dm/callback' }));
    app.get('/auth/dm/callback', passport.authenticate('dropbox-oauth2', { callbackURL: ov_config.wsbase+'/auth/dm/callback' }), dboxoauth);
  }

  if (ov_config.jwt_token_test)
    app.get('/auth/tokentest', tokentest);

  return app;
}
