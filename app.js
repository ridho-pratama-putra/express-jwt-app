const app = require('./appServer.js');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App server listening at http://localhost:${PORT}`));
