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
                .then( (response) => {
                    expect(response.body).toEqual(
                        expect.objectContaining({
                            accessToken: expect.any(String),
                            refreshToken: expect.any(String)
                        })
                    )
                })
        })
    })
})
