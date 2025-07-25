const express = require("express");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { generateAccessToken, generateRefreshToken } = require("./auth");

const port = 3000;

const app = express();
app.use(express.json());

let accessTokenBlacklist = [];
let refreshTokens = [];

const posts = [
  {
    username: 'Harry',
    title: "Post 1",
    content: "This is the content of post 1",
  },
  {
    username: 'Phuot',
    title: "Post 2",
    content: "This is the content of post 2",
  },
  {
    username: 'Harry',
    title: "Post 3",
    content: "This is the content of post 3",
  },
];

// Get posts from username
app.get('/posts', authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.username));
});

// Login to get access and refresh token
app.post('/login', (req, res) => {
  const { username } = req.body;
  const user = { username };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
})

// Regenerate access token from refresh token
app.post('/token', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    refreshTokens = refreshTokens.filter(currentRefreshToken => currentRefreshToken !== refreshToken);

    const accessToken = generateAccessToken({ username: user.username });
    const newRefreshToken = generateRefreshToken({ username: user.username });

    refreshTokens.push(newRefreshToken);

    res.json({ accessToken, refreshToken: newRefreshToken });
  })
})

app.delete('/logout', (req, res) => {
  const { accessToken, refreshToken } = req.body;
  refreshTokens = refreshTokens.filter(currentRefreshToken => currentRefreshToken !== refreshToken);
  accessTokenBlacklist.push(accessToken);
  res.sendStatus(204);
})

// 🔐 Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  if (accessTokenBlacklist.includes(token)) {
    return res.sendStatus(403);
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  })
}


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
