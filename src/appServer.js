require('dotenv').config()
const express = require('express')
const appServer = express()
const jwt = require('jsonwebtoken')

appServer.use(express.json())

appServer.get('/', (req, res) => {
  res.send('Hello World!')
})

function authenticateUser (req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) {
    return res.sendStatus(401)
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      // console.log(err)
      return res.sendStatus(403)
    }
    req.user = user
    next()
  })
}

appServer.get('/posts', authenticateUser, (req, res) => {
  res.json([{
    content: 'first  post',
    creator: 'user A',
  }, {
    content: 'second  post',
    creator: 'user B',
  }].filter(post => post.creator === req.user.name)
  )
})
module.exports = appServer
