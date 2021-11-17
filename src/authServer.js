require('dotenv').config({ path: '/home/abc/Documents/express-jwt-app/.env' })
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const User = require('./models/user')
const responseFactory = require('./models/response')
const { HTTP_STATUS_OK, HTTP_STATUS_CREATED, HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAUTHORIZED, HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_STATUS_CONFLICT } = require('./constants/HttpStatus')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const cors = require('cors')
var morgan = require('morgan')

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
// passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID,
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//     callbackURL: process.env.CALLBACK_URL,
//   },
//   function (accessToken, refreshToken, profile, done) {
//     // passport callback function
//     // check if user already exists in our db with the given profile ID
//     User.findOne({
//       $or: [
//         { googleId: profile.id, },
//         { email: profile.emails[0].value, }
//       ],
//     }).then((currentUser) => {
//       if (currentUser && currentUser.googleId) { // registered with google account
//         done(null, currentUser)
//       } else if (currentUser && currentUser.email) { // registered manually
//         done(null, false, { message: '', })
//       } else { // if not, create a new user
//         new User({
//           displayName: profile.displayName,
//           googleId: profile.id,
//           email: profile.emails[0].value,
//         }).save().then((newUser) => {
//           done(null, newUser)
//         })
//       }
//     })
//   }
// ))

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
  failureRedirect: '/failed'
}), (req, res) => {
  const { user, } = req
  const { email, } = user
  // generate jwt as log in process
  const accessToken = generateAccessTokenWithExipration({ email, })
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
  const { email } = req.body
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

app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  const authHeader = req.headers.authorization
  if (authHeader === undefined || !authHeader.startsWith('Bearer ')) {
    return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
  }
  if (refreshToken == null) {
    return res.sendStatus(HTTP_STATUS_UNAUTHORIZED)
  }

  let token = authHeader && authHeader.split(' ')[1].trim()

  User.findOne({ 'authentication.refreshToken': refreshToken, }, (err, doc) => {
    if (err || doc === null) {
      return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
        code: '06',
        description: 'You r not registered',
      }, [{}]))
    }

    jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        return res.sendStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR)
      }
      // console.log('decoded :: ', decoded)
      const accessToken = generateAccessTokenWithExipration(decoded)
      if (token === accessToken) {
        console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
      }
      doc.authentication = {
        token: accessToken,
        refreshToken,
      }
      // console.log('data changed :: ', doc.authentication)
      doc.save((err, doc) => {
        if (err) {
          // console.log(err)
          return res.status(HTTP_STATUS_BAD_REQUEST).json(responseFactory({
            code: '06',
            description: 'Failed to update token',
          }, [{}]))
        }
        // console.log(doc)
        res.status(HTTP_STATUS_OK).json(responseFactory({
          code: '00',
          description: 'Refresh token success',
        }, [{
          accessToken: accessToken,
          refreshToken,
        }]))
      })
    })
  })
})

app.delete('/logout', (req, res) => {
  let token, authHeader = req.headers.authorization
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7, authHeader.length)
  } else {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'Unautorized',
    }, [{}]))
  }

  User.findOne({ 'authentication.refreshToken': token }, (err, doc) => {
    if (err || doc === null) {
      return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
        code: '06',
        description: 'token not found',
      }, [{}]))
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
  return jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '50s', })
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

    doc.comparePassword(password, (err, isMatch) => {
      if (err) {
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

app.get('/', (req, res) => {
  let authHeader = req.headers.authorization
  let token = authHeader && authHeader.split(' ')[1].trim()
  const contoh = 'contoh'
  console.log('token', token)
  console.log('tokenconton', contoh)
  let isJWTValid = true
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      isJWTValid = false
    }
  })
  if (isJWTValid) {
    res.sendStatus(HTTP_STATUS_OK)
  } else {
    return res.status(HTTP_STATUS_UNAUTHORIZED).json(responseFactory({
      code: '06',
      description: 'Your jwt invalid',
    }, [{}]))
  }
})
module.exports = app
