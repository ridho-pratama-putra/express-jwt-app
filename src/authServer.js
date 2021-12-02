require('dotenv').config({ path: '/home/abc/Documents/express-jwt-app/.env', })
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const responseFactory = require('./models/response')
const { HTTP_STATUS_OK, HTTP_STATUS_CREATED, HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAUTHORIZED, HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_STATUS_CONFLICT, } = require('./constants/HttpStatus')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const cors = require('cors')
const morgan = require('morgan')

const originalSend = app.response.send
app.response.send = function sendOverWrite (body) {
  originalSend.call(this, body)
  this.__custombody__ = body
}
morgan.token('body', (req) => JSON.stringify(req.body))
morgan.token('response', (_, res) => JSON.stringify(res.__custombody__))
app.use(morgan(':date[iso] :remote-addr :method :url :status :body :response - :response-time ms'))
app.use(express.json())
app.use(passport.initialize())
app.use(cors())
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL,
},
function (accessToken, refreshToken, profile, done) {
  // passport callback function
  // check if user already exists in our db with the given profile ID
  User.findOne({
    $or: [
      { googleId: profile.id, },
      { email: profile.emails[0].value, }
    ],
  }).then((currentUser) => {
    if (currentUser && currentUser.googleId) { // registered with google account
      done(null, currentUser)
    } else if (currentUser && currentUser.email) { // registered manually
      done(null, false, { message: '', })
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

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}))

app.get('/failed', (req, res) => {
  res.status(HTTP_STATUS_CONFLICT).json(responseFactory({
    code: '06',
    description: 'Failed to log in.',
  }, [{}]))
})

app.get('/auth/google/redirect', passport.authenticate('google', {
  session: false,
  failureRedirect: '/failed',
}), (req, res) => {
  const { user, } = req
  const { email, } = user
  const accessToken = generateAccessTokenWithExpiration({ email, })
  const refreshToken = jwt.sign({ email, }, process.env.REFRESH_ACCESS_TOKEN_SECRET)
  user.authentication = {
    token: accessToken,
    refreshToken,
  }
  user.save((err, doc) => {
    if (err) {
      return res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json(responseFactory({
        code: '06',
        description: 'Database error',
      }, [{}]))
    }
    res.cookie('accessToken', accessToken)
    res.cookie('refreshToken', refreshToken)
    res.redirect('http://localhost:3000/')
  })
})

app.post('/internal-account', (req, res) => {
  const { email, } = req.body
  User.findOne({ email: email, }).then((currentUser) => {
    if (currentUser && currentUser.googleId && !currentUser.password) {
      return res.status(HTTP_STATUS_OK).json(responseFactory({
        code: '06',
        description: 'please login with your google account',
      }, []))
    } else if (currentUser) {
      return res.status(HTTP_STATUS_OK).json(responseFactory({
        code: '00',
        description: 'success',
      }, []))
    } else {
      return res.status(HTTP_STATUS_OK).json(responseFactory({
        code: '06',
        description: 'account not found',
      }, []))
    }
  })
})

app.post('/token', async (req, res) => {
  const refreshToken = req.body.refreshToken
  const authHeader = req.headers.authorization
  if (authHeader === undefined || !authHeader.startsWith('Bearer ')) {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'You r not authorized',
    }, [{}]))
  }
  if (refreshToken == null) {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'You r not registered',
    }, [{}]))
  }

  const verifiedRefreshToken = await jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (error, decoded) => {
    if (error) {
      return false
    }
    return decoded
  })

  if (verifiedRefreshToken === false) {
    return res.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).json(responseFactory({
      code: '06',
      description: 'please relogin',
    }, [{}]))
  }

  const { email, } = verifiedRefreshToken

  const searchUser = await User.findOne({ email: email, }, (err, doc) => {
    if (err) {
      return false
    }
    return doc
  })

  if (searchUser === false) {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'Database error',
    }, [{}]))
  }

  if (searchUser === null) {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'You r not registered',
    }, [{}]))
  }

  const accessToken = generateAccessTokenWithExpiration({ email, })
  searchUser.authentication = {
    token: accessToken,
    refreshToken,
  }
  await searchUser.save((saveError) => {
    if (saveError) {
      return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
        code: '06',
        description: 'Failed to update token',
      }, [{}]))
    }
    return res.status(HTTP_STATUS_OK).json(responseFactory({
      code: '00',
      description: 'Refresh token success',
    }, [{
      accessToken: accessToken,
      refreshToken,
    }]))
  })
})

function generateAccessTokenWithExpiration (email) {
  return jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '10s', })
}

function generateRefreshTokenWithExpiration (email) {
  return jwt.sign(email, process.env.REFRESH_ACCESS_TOKEN_SECRET, { expiresIn: '1d', })
}

app.post('/login', (req, res) => {
  const { email, password, } = req.body
  User.findOne({ email, }, (err, doc) => {
    if (err || doc === null) {
      return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
        code: '06',
        description: 'You r not registered',
      }, [{}]))
    }

    doc.comparePassword(password, (errCompare, isMatch) => {
      if (errCompare) {
        return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'Failed to login',
        }, [{ err, }]))
      }
      if (!isMatch) {
        return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
          code: '06',
          description: 'Password not match',
        }, [{}]))
      }

      const accessToken = generateAccessTokenWithExpiration({ email, })
      const refreshToken = generateRefreshTokenWithExpiration({ email, })
      doc.authentication = {
        token: accessToken,
        refreshToken,
      }
      doc.save((errSave) => {
        if (errSave) {
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

app.get('/', (req, res) => {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(' ')[1].trim()
  let isJWTValid = true
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err) => {
    if (err) {
      isJWTValid = false
    }
  })
  if (isJWTValid) {
    return res.status(HTTP_STATUS_OK).json(responseFactory({
      code: '00',
      description: 'Content retrieved',
    }, [{}]))
  } else {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'Your jwt invalid',
    }, [{}]))
  }
})
module.exports = app
