const request = require('supertest')
const app = require('../src/authServer') // the express server
const db = require('./db')
const User = require('../src/models/user')
const passport = require('passport')
const jwt = require('jsonwebtoken')

describe('AuthServer', () => {
  beforeAll(async () => {
    passport.authenticate = jest.fn((authType, options, callback) => () => {
      callback('This is an error', null)
    })
    await db.connect()
  })
  afterAll(async () => await db.closeDatabase())
  afterEach(async () => {
    jest.restoreAllMocks()
    await db.clearDatabase()
  })

  describe('/login', () => {
    const sign = jest.spyOn(jwt, 'sign');
    sign.mockImplementation(() => () => ({ signed: 'true' }));

    it('should return array of object contain token and refresh token', async () => {
      const user = new User({
        email: 'email@emal.com',
        password: 'userA'
      })
      await user.save()

      await request(app)
        .post('/login').send({
          email: 'email@emal.com',
          password: 'userA'
        }).expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200)
        .then((response) => {
          expect(response.body.result[0].accessToken).not.toBe(null)
          expect(response.body.result[0].refreshtoken).not.toBe(null)
        })
    })
  })

  describe('/token', () => {
    it('should return 401 when no refresh token', async () => {
      await request(app)
        .post('/token')
        .set('Authorization', 'Bearer invalid token')
        .send({
          refreshToken: null
        })
        .expect(401)
    })

    it('should return 200 when success refresh token', async () => {
      const verify = jest.spyOn(jwt, 'verify');
      verify.mockImplementation(() => ({ email: 'email@emal.com' }));
      const sign = jest.spyOn(jwt, 'sign');
      sign.mockImplementation(() => ({ signed: 'true' }));
      const user = new User({
        username: 'user A',
        email: 'email@emal.com',
        password: 'password',
      })
      await user.save()
      await request(app)
        .post('/token')
        .set('Authorization', 'Bearer expired token')
        .send({
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(200)
        .then((response) => {
          expect(response.body.result[0].accessToken).not.toBe(null)
          expect(response.body.result[0].refreshToken).not.toBe(null)
        })
    })

    it('should return 500 when verify token return false', async () => {
      const verify = jest.spyOn(jwt, 'verify');
      verify.mockImplementation(() => false);
      const user = new User({
        username: 'user A',
        email: 'email@emal.com',
        password: 'password',
      })
      await user.save()
      await request(app)
        .post('/token')
        .set('Authorization', 'Bearer expired token')
        .send({
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(500)
    })

    it('should return unauthorized when called without bearer authorized header', async () => {
      const user = new User({
        username: 'user A',
        email: 'email@emal.com',
        password: 'password',
      })
      await user.save()
      await request(app)
        .post('/token')
        .set('Authorization', 'expired token')
        .send({
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(401)
    })

    it('should return unauthorized when called without authorized header', async () => {
      const user = new User({
        username: 'user A',
        email: 'email@emal.com',
        password: 'password',
      })
      await user.save()
      await request(app)
        .post('/token')
        .send({
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(401)
    })
  })

  describe('/register', () => {
    it('should return 400 failed to create account when record already exist', async () => {
      const user = new User({
        email: 'email@emal.com',
        password: 'password'
      })
      await user.save()
      const res = await request(app)
        .post('/register').send({
          email: 'email@emal.com',
          password: 'password'
        })
        .expect(400)
      expect(res.body.status.code).toEqual('06')
      expect(res.body.status.description).toEqual('failed to crate account')
    })

    it('should return 201 when success create record', async () => {
      const res = await request(app)
        .post('/register').send({
          email: 'email@emal.com',
          password: 'password'
        })
        .expect(201)
      expect(res.body.status.code).toEqual('00')
      expect(res.body.status.description).toEqual('Success')
    })
  })

  describe('/internal-account', function () {
    it('should return 200 when users email not yet registered', async () => {
      const res = await request(app)
        .post('/internal-account').send({
          email: 'email@emal.com',
        })
        .expect(200)
      expect(res.body.status.description).toEqual('account not found')
    })

    it('should return 200 when users email is exist only on external account: google', async () => {
      const user = new User({
        googleId: 'email@emal.com',
        email: 'email@emal.com',
      })
      await user.save()
      const res = await request(app)
        .post('/internal-account').send({
          email: 'email@emal.com',
        })
        .expect(200)
      expect(res.body.status.description).toEqual('please login with your google account')
    })

    it('should return 200 when users email is exist on email', async () => {
      const user = new User({
        email: 'email@emal.com',
        password: 'password'
      })
      await user.save()
      await request(app)
        .post('/internal-account').send({
          email: 'email@emal.com',
        })
        .expect(200)
    })
  })

  describe('/user/access-token/:token', () => {
    it('should return success when given access token is invalid', async () => {
      const verify = jest.spyOn(jwt, 'verify');
      verify.mockImplementation(() => false);
      const res = await request(app)
        .get('/user/access-token')
        .set('Authorization', 'Bearer invalid token')
        .send()
        .expect(401)
      expect(res.body.status.description).toEqual('Access Token Expired')
    })

    it('should return success when given access token is valid', async () => {
      const verify = jest.spyOn(jwt, 'verify');
      verify.mockImplementation(() => {decoded: 'email@rmail.com'});
      const res = await request(app)
        .get('/user/access-token')
        .set('Authorization', 'Bearer valid token')
        .send()
        .expect(200)
      expect(res.body.status.description).toEqual('Access Token Valid')
    })
  })
})
