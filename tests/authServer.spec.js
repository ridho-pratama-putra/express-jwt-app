const request = require('supertest');
const app = require('../src/authServer'); // the express server
const db = require('./db');
const User = require('../src/models/user')

describe('AuthServer', () => {
  beforeAll(async () => await db.connect())
  afterAll(async () => await db.closeDatabase())
  afterEach(async () => {
    jest.restoreAllMocks()
    await db.clearDatabase()
  })

  describe('/login', () => {
    it('should return array of object contain token and refresh token', async () => {
      const user = new User({ username: 'user A', email: 'email@emal.com', password: 'userA' })
      await user.save()

      await request(app)
        .post('/login').send({
          username: 'user A',
          password: 'userA'
        }).expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200)
        .then((response) => {
          expect(response.body).toHaveProperty('result') // true
          expect(response.body.result).toStrictEqual(expect.arrayContaining([
            expect.objectContaining({
              accessToken: expect.any(String),
              refreshToken: expect.any(String)
            })
          ]));
        });
    });
  });

  describe('/token', () => {
    it('should return 401 when no refresh token listed', async () => {
      await request(app)
        .post('/token').send({
          token: null
        })
        .expect(401);
    });
    it('should return 403 when no refresh token listed', async () => {
      await request(app)
        .post('/token').send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(401);
    });
  });

  describe('/logout', () => {
    it('should return 204 after delete refresh token', async () => {
      await request(app)
        .delete('/logout').send({
          token: 'fake invalid token'
        })
        .expect(401);
    });
  });

  describe('/register', () => {
    it('should return 400 failed to create account when required email not fulfilled', async () => {
      const res = await request(app)
        .post('/register').send({
          username: 'my username',
          password: 'p@ssw0d'
        })
        .expect(400)
        expect(res.body.status.code).toEqual('06')
        expect(res.body.status.description).toEqual('failed to crate account')
    });

    it('should return 400 failed to create account when record already exist', async () => {
      const user = new User({
        username: 'userName',
        email: 'email@emal.com',
        password: 'password'
      })
      await user.save()
      const res = await request(app)
        .post('/register').send({
          username: 'userName',
          email: 'email@emal.com',
          password: 'password'
        })
        .expect(400)
      expect(res.body.status.code).toEqual('06')
      expect(res.body.status.description).toEqual('failed to crate account')
    });
  });

  it('should return 201 when success create record', async () => {
    const res = await request(app)
      .post('/register').send({
        username: 'userName',
        email: 'email@emal.com',
        password: 'password'
      })
      .expect(201)
    expect(res.body.status.code).toEqual('00')
    expect(res.body.status.description).toEqual('Success')
  });
});
