require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const Authentication = require('./models/authentication')
const responseFactory = require('./models/response')

app.use(express.json())
let refreshTokens = []

app.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) {
    return res.sendStatus(401)
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.sendStatus(403)
  }
  jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403)
    }
    const accessToken = generateAccessTokenWithExipration({ name: user.name, })
    res.json({ accessToken, })
  })
})

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

function generateAccessTokenWithExipration (user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '100s', })
}

app.post('/login', (req, res) => {
  const { username, password } = req.body

  User.findOne({ username }, (err, doc) => {

    if (err) {
      console.log(err)
      res.status(401)
      return
    }

    doc.comparePassword(password, (err, isMatch) => {
      if (err) return res.status(400).json(responseFactory({
        code: '06',
        description: 'failed to login'
      }, [{ err }]))
      if (!isMatch) {
        return res.status(400).json(responseFactory({
          code: '06',
          description: 'Password not match'
        }, [{}]))
      }

      const userForJwt = {
        username, password
      }

      const accessToken = generateAccessTokenWithExipration(userForJwt)
      const refreshToken = jwt.sign(userForJwt, process.env.REFRESH_ACCESS_TOKEN_SECRET)

      doc.authentication = {
        token: accessToken,
        refreshToken,
      }
      doc.save( (err, doc) => {
        if (err) {
          console.log(err)
          return res.status(400).json(responseFactory({
            code: '06',
            description: 'Failed to update token'
          }, [{}]))
        }
        res.status(200).json(responseFactory({
          code: '00',
          description: 'Success'
        }, [{
          accessToken,
          refreshToken
        }]))
      })
    })
  })
})

app.post('/register', async (req, res) => {
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
  })

  await user.save((err, doc) => {
    if (err) {
      console.log(err)
      res.status(400).json(responseFactory({
        code: '06',
        description: 'failed to crate account'
      }, [{ err }]))
      return
    }

    res.status(201).json(responseFactory({
      code: '00',
      description: 'Success'
    }, [doc]))
  })
})

module.exports = app
