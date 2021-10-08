const mongoose = require('mongoose')
const Schema = mongoose.Schema

const AuthenticationSchema = new Schema({
  token: {
    type: String,
  },
  refreshToken: {
    type: String,
  },
})

module.exports = AuthenticationSchema
