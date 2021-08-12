require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const responseFactory = require('./models/response')
const { HTTP_STATUS_OK, HTTP_STATUS_CREATED, HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAUTHORIZED, } = require('./constants/HttpStatus')

app.use(express.json())

app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  if (refreshToken == null) {
    return res.sendStatus(401)
  }

  User.findOne({ 'authentication.refreshToken': refreshToken, }, (err, doc) => {
    if (err || doc === null) {
      return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
    }

    jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (err, username) => {
      if (err) {
        return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
      }
      const accessToken = generateAccessTokenWithExipration(username)
      res.json({ accessToken, })
    })
  })
})

app.delete('/logout', (req, res) => {
  User.findOne({ 'authentication.token': req.body.token, }, (err, doc) => {
    if (err || doc === null) {
      return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
    }

    doc.authentication = {
      token: null,
      refreshToken: null,
    }
    doc.save((err, doc) => {
      if (err) {
        // console.log(err)
        return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'Failed to logout',
        }, [{}]))
      }
      return res.status(HTTP_STATUS_OK).json(responseFactory({
        code: '00',
        description: 'Logout success',
      }, [{}]))
    })
  })
})

function generateAccessTokenWithExipration (user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '100s', })
}

app.post('/login', (req, res) => {
  const { username, password, } = req.body

  User.findOne({ username, }, (err, doc) => {
    if (err) {
      // console.log(err)
      res.status(HTTP_STATUS_UNAUTHORIZED)
      return
    }

    doc.comparePassword(password, (err, isMatch) => {
      if (err) {
        return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'failed to login',
        }, [{ err, }]))
      }
      if (!isMatch) {
        return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'Password not match',
        }, [{}]))
      }

      const accessToken = generateAccessTokenWithExipration({ username, })
      const refreshToken = jwt.sign({ username, }, process.env.REFRESH_ACCESS_TOKEN_SECRET)
      doc.authentication = {
        token: accessToken,
        refreshToken,
      }
      doc.save((err, doc) => {
        if (err) {
          // console.log(err)
          return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
            code: '06',
            description: 'Failed to update token',
          }, [{}]))
        }
        res.status(HTTP_STATUS_OK).json(responseFactory({
          code: '00',
          description: 'Success',
        }, [{
          accessToken,
          refreshToken,
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
      // console.log(err)
      res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
        code: '06',
        description: 'failed to crate account',
      }, [{ err, }]))
      return
    }

    res.status(HTTP_STATUS_CREATED).json(responseFactory({
      code: '00',
      description: 'Success',
    }, [doc]))
  })
})

module.exports = app
