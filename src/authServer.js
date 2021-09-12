require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const responseFactory = require('./models/response')
const { HTTP_STATUS_OK, HTTP_STATUS_CREATED, HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAUTHORIZED, } = require('./constants/HttpStatus')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const cookieSession = require('cookie-session')

passport.serializeUser(function (user, done) {
  console.log('serialize user ', user)
  done(null, user.id)
})

passport.deserializeUser(function (userId, done) {
  console.log('deserialize user ', userId)
  User.findById(userId).then(user => {
    done(null, user)
  })
})

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL,
},
function (accessToken, refreshToken, profile, done) {
  // passport callback function
  // check if user already exists in our db with the given profile ID
  User.findOne({ googleId: profile.id, }).then((currentUser) => {
    // console.log('currentUser', currentUser)
    // console.log('accessToken', accessToken)
    // console.log('refreshToken', refreshToken)
    // console.log('profile', profile)
    if (currentUser) {
      // if we already have a record with the given profile ID
      done(null, currentUser)
    } else {
      // if not, create a new user
      new User({
        displayName: profile.displayName,
        googleId: profile.id,
        email: profile.emails[0].value,
        authentication: {
          accessToken: accessToken,
        },
      }).save().then((newUser) => {
        done(null, newUser)
      }).catch(err => {
        res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'failed to crate account',
        }, [{ err, }]))
      });
    }
  })
}
))

app.use(express.json())

app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  if (refreshToken == null) {
    return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
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

app.use(cookieSession({
  // milliseconds of a day
  maxAge: 24 * 60 * 60 * 1000,
  keys: [process.env.GOOGLE_COOKIE_KEY],
}))
app.use(passport.initialize())
app.use(passport.session())

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}))

app.get('/auth/google/redirect', passport.authenticate('google'), (req, res) => {
  console.log(req.user)
  res.send('you reached the redirect URI')
})
module.exports = app
