require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const responseFactory = require('./models/response')
const { HTTP_STATUS_OK, HTTP_STATUS_CREATED, HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAUTHORIZED, HTTP_STATUS_CONFLICT, } = require('./constants/HttpStatus')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy

app.use(express.json())
app.use(passport.initialize())
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
  },
  function (accessToken, refreshToken, profile, done) {
    // passport callback function
    // check if user already exists in our db with the given profile ID
    console.log('using GoogleStrategy :: ')
    User.findOne({
      $or: [
        { googleId: profile.id, },
        { email: profile.emails[0].value }
      ]
    }).then((currentUser) => {
      if (currentUser && currentUser.googleId) { // registered with google account
        done(null, currentUser)
      } else if (currentUser && currentUser.email) { // registered manually
        done(null, false, { message: 'Seems already registered without google account, Do you want to reset your password?' })
      } else { // if not, create a new user
        new User({
          displayName: profile.displayName,
          googleId: profile.id,
          email: profile.emails[0].value,
        }).save().then((newUser) => {
          done(null, newUser)
        })
      }
    })
  }
))

app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  if (refreshToken == null) {
    return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
  }

  User.findOne({ 'authentication.refreshToken': refreshToken, }, (err, doc) => {
    if (err || doc === null) {
      return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
    }

    jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (err, email) => {
      if (err) {
        return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
      }
      const accessToken = generateAccessTokenWithExipration(email)
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

function generateAccessTokenWithExipration (email) {
  return jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '100s', })
}

app.post('/login', (req, res) => {
  const { email, password, } = req.body

  User.findOne({ email, }, (err, doc) => {
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

      const accessToken = generateAccessTokenWithExipration({ email, })
      const refreshToken = jwt.sign({ email, }, process.env.REFRESH_ACCESS_TOKEN_SECRET)
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

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}))

app.get('/failed', (req, res) => {
  res.status(HTTP_STATUS_CONFLICT).json(responseFactory({
    code: '06',
    description: 'failed to log in',
  }, [{ }]))
})

app.get('/auth/google/redirect', passport.authenticate('google', {session: false}), (req, res) => {
  const { user } = req
  const { email } = user
  // generate jwt as log in process
  const accessToken = generateAccessTokenWithExipration({ email, })
  const refreshToken = jwt.sign({ email, }, process.env.REFRESH_ACCESS_TOKEN_SECRET)
  user.authentication =  {
    token: accessToken,
    refreshToken,
  }
  user.save((err, doc) => {
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

module.exports = app
