
import express from 'express';
import expressLogging from 'express-logging';
import expressSession from 'express-session';
import crypto from 'crypto';
import logger from 'logops';
import redis from 'redis';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import FacebookStrategy from 'passport-facebook';
import GoogleStrategy from 'passport-google-oauth20';

const ovi_config = {
  wsbase: ( process.env.WSBASE ? process.env.WSBASE : 'http://localhost:8080' ),
  ip_header: ( process.env.CLIENT_IP_HEADER ? process.env.CLIENT_IP_HEADER : null ),
  redis_host: ( process.env.REDIS_HOST ? process.env.REDIS_HOST : 'localhost' ),
  redis_port: ( process.env.REDIS_PORT ? process.env.REDIS_PORT : 6379 ),
  session_secret: ( process.env.SESSION_SECRET ? process.env.SESSION_SECRET : crypto.randomBytes(48).toString('hex') ),
  jwt_secret: ( process.env.JWS_SECRET ? process.env.JWS_SECRET : crypto.randomBytes(48).toString('hex') ),
  jwt_iss: ( process.env.JWS_ISS ? process.env.JWS_ISS : 'example.com' ),
  DEBUG: ( process.env.DEBUG ? true : false ),
};

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
  res.redirect('OurVoiceApp://login?jwt=' + jwt.sign(u, ovi_config.jwt_secret));
}

function poke(req, res) {
  if (rc.connected)
    return res.sendStatus(200);
  return res.sendStatus(500);
}

// Initialize http server
var connectRedis = require('connect-redis')(expressSession);
const app = express();
app.use(expressLogging(logger));
app.use(expressSession({
    store: new connectRedis({client: rc}),
    secret: ovi_config.session_secret,
    saveUninitialized: false,
    resave: false
}));

// Initialize Passport
app.use(passport.initialize());

// require ip_header if config for it is set
if (!ovi_config.DEBUG) {
  app.use(function (req, res, next) {
    if (ovi_config.ip_header && !req.header(ovi_config.ip_header)) {
      console.log('Connection without '+ovi_config.ip_header+' header');
      res.status(400).send();
    }
    else next();
  });
}

// internal routes
app.get('/poke', poke);

// Set up auth routes
app.get('/auth/fm', passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', scope: ['email']} ));
// google accepts the custom loginHint
app.get('/auth/gm', function(req, res, next) {
  passport.authenticate('google', { loginHint: req.query.loginHint, callbackURL: ovi_config.wsbase+'/auth/gm/callback', scope: ['profile', 'email'] }
  )(req, res, next)});
app.get('/auth/fm/callback', passport.authenticate('facebook', { callbackURL: ovi_config.wsbase+'/auth/fm/callback', failureRedirect: '/auth/fm' }), moauthredir);
app.get('/auth/gm/callback', passport.authenticate('google',   { callbackURL: ovi_config.wsbase+'/auth/gm/callback', failureRedirect: '/auth/gm' }), moauthredir);

// Launch the server
const server = app.listen(8080, () => {
  const { address, port } = server.address();
  console.log('sm-oauth express');
  console.log(`Listening at http://${address}:${port}`);
});

