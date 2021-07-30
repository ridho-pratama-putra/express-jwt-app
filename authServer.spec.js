const request = require('supertest');
const app = require('./authServer'); // the express server

describe('AuthServer', () => {
  describe('/login', () => {
    it('return array of object contain token and refresh token', async () => {
      await request(app)
        .post('/login').send({
          username: 'user A'
        }).expect('Content-Type', 'application/json; charset=utf-8')
        .expect(200)
        .then((response) => {
          expect(response.body).toEqual(
            expect.objectContaining({
              accessToken: expect.any(String),
              refreshToken: expect.any(String)
            })
          );
        });
    });
  });

  describe('/token', () => {
    it('return 401 when no refresh token listed', async () => {
      await request(app)
        .post('/token').send({
          token: null
        })
        .expect(401);
    });
    it('return 403 when no refresh token listed', async () => {
      await request(app)
        .post('/token').send({
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidXNlciBBIiwiaWF0IjoxNjI3MzEwOTYxfQ.QAETcsieJblDV2jZ2seg4iZEKjcWfAlYQcRHGamDKoc'
        })
        .expect(403);
    });
  });

  describe('/logout', () => {
    it('return 204 after delete refresh token', async () => {
      await request(app)
        .delete('/logout').send({
          token: 'fake invalid token'
        })
        .expect(204);
    });
  });
});
