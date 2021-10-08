require('dotenv').config()
const app = require('./authServer.js')
const PORT = process.env.PORT || 4000
const mongoose = require('mongoose')

mongoose
  .connect(`${process.env.MONGODB_PREFIX_URL}${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}${process.env.MONGODB_POSTFIX_URL}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    app.listen(PORT, () => console.log(`Auth server listening at http://localhost:${PORT}`))
  })
