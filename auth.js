const app = require('./authServer.js')
const PORT = process.env.PORT || 4000
const mongoose = require("mongoose")
const databaseUrl = "mongodb+srv://xpress-jwt-lesson:dwL7tQWPhSkmIiV2@cluster0.m2bx1.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
mongoose
    .connect(databaseUrl, { useNewUrlParser: true })
    .then(() => {
        app.listen(PORT, () => console.log(`Auth server listening at http://localhost:${PORT}`))
    })
