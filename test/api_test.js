
import { expect } from 'chai';
import redis from 'redis-mock';
import supertest from 'supertest';
import jwt from 'jsonwebtoken';
import keypair from 'keypair';
import fs from 'fs';

import { ov_config, getConfig } from '../lib/ov_config';
import { doExpressInit } from '../lib/express';

var pair = {};
var public_key;

var app;
var api;

if (process.env.TEST_TARGET) {
  api = supertest(process.env.TEST_TARGET);
} else {
  app = doExpressInit(false, redis);
  api = supertest(app);
}

describe('API smoke', function () {

  before(async () => {
    // just use a static key to save time if we're debugging
    if (ov_config.DEBUG)
      pair.public = fs.readFileSync('./test/debug.pub');
    else
      pair = keypair();
  });

  after(() => {
    if (app) app.rc.quit();
  });

  it('getConfig negative test', () => {
    let error = false;
    try {
      getConfig("blah", true, true);
      error = true;
    } catch (e) {}
    expect(error).to.equal(false);
  });

  it('poke 200', async () => {
    const r = await api.get('/poke');
    expect(r.statusCode).to.equal(200);
  });

  it('/auth/pubkey 200', async () => {
    const r = await api.get('/auth/pubkey');
    expect(r.statusCode).to.equal(200);
    public_key = r.body.toString();
    expect(public_key).to.match(/BEGIN.*KEY/);
    expect(public_key).to.match(/END.*KEY/);
  });

  it('/auth/jwt 401', async () => {
    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
    expect(r.statusCode).to.equal(401);
  });

  it('/auth/jwt 400', async () => {
    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
      .send({
        apiKey: "passing_an_#_invalid_har",
      });
    expect(r.statusCode).to.equal(400);
  });

  it('/auth/jwt 400', async () => {
    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
      .send({
        apiKey: "short",
      });
    expect(r.statusCode).to.equal(400);
  });

  it('/auth/jwt 400', async () => {
    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
      .send({
        apiKey: "this_string_is_way_to_long_beceause_it_is_more_than_64_characters_which_is_a_lot_but_not_really",
      });
    expect(r.statusCode).to.equal(400);
  });

  it('/auth/jwt 401', async () => {
    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
    expect(r.statusCode).to.equal(401);
  });

  it('/auth/jwt 200', async () => {
    let apiKey = "Test-ID-"+Math.ceil(Math.random()*10000000);

    const r = await api.post('/auth/jwt')
      .set('Content-Type', 'application/json')
      .set('User-Agent', 'OurVoiceUSA/test')
      .send({
        apiKey: apiKey,
      });
    expect(r.statusCode).to.equal(200);

    let obj = jwt.verify(r.body.jwt, public_key);
    expect(r.get('x-jwt-iss')).to.equal(obj.iss);
    expect(obj.sub).to.equal(apiKey);
    expect(obj).to.have.property("iat");
    expect(obj).to.have.property("exp");
    expect(obj).to.have.property("disclaimer");

    let exception = false;
    try {
      jwt.verify(r.body.jwt, pair.public);
    } catch (e) {
      exception = true;
    }
    expect(exception).to.equal(true);

  });

});
