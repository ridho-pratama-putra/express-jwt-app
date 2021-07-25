require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())
let refreshTokens = []

app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) { return res.sendStatus(401) }
    if(!refreshTokens.includes(refreshToken)) { return res.sendStatus(403) }
    jwt.verify(refreshToken, process.env.REFRESH_ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) { return res.sendStatus(403) }
        const accessToken = generateAccessTokenWithExipration({ name: user.name })
        res.json({ accessToken })
    })
})

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

function generateAccessTokenWithExipration(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '100s' })
}

app.post('/login', (req, res) => {
    // authenticate user
    const  { username } = req.body
    const user = { name: username }
    const accessToken = generateAccessTokenWithExipration(user)

    const refreshToken = jwt.sign(user, process.env.REFRESH_ACCESS_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.json({ accessToken, refreshToken })
})

module.exports = app
