require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')

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
  // authenticate user
  const { username, } = req.body
  const user = { name: username, }
  const accessToken = generateAccessTokenWithExipration(user)

  const refreshToken = jwt.sign(user, process.env.REFRESH_ACCESS_TOKEN_SECRET)
  refreshTokens.push(refreshToken)
  res.json({
    accessToken,
    refreshToken,
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
      res.status(400).json({
        status: '06',
        description: 'failed to crate account',
      })
      return
    }

    res.status(201).json({
      status: '00',
      description: 'success crate account',
      response: {
        doc,
      },
    })
  })
})

module.exports = app
