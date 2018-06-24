
var expect = require('chai').expect;
var supertest = require('supertest');
var jwt = require('jsonwebtoken');
var api = supertest('http://localhost:8080');
var keypair = require('keypair');

var pair;
var public_key;

describe('API smoke', function () {

  before(async () => {
    pair = keypair();
  });

  it('poke 200', async () => {
    const r = await api.get('/poke');
    expect(r.statusCode).to.equal(200);
  });

  it('/auth/pubkey 200', async () => {
    const r = await api.get('/auth/pubkey');
    expect(r.statusCode).to.equal(200);
    public_key = r.body.toString();
    expect(public_key).to.match(/BEGIN CERTIFICATE/);
    expect(public_key).to.match(/END CERTIFICATE/);
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

