const app = require('./authServer.js')
const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`Auth server listening at http://localhost:${PORT}`))