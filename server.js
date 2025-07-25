const express = require("express");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { generateAccessToken, generateRefreshToken } = require("./auth");

const port = 3000;

const app = express();
app.use(express.json());

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
  res.json({ accessToken, refreshToken })
})

// Regenerate access token from refresh token
app.post('/token', (req, res) => {
  const { token } = req.body;
  if (!token) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403);

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken })
  })
})

app.delete('/logout', (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(refreshToken => refreshToken !== token);
  res.sendStatus(204);
})

// 🔐 Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  })
}


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
