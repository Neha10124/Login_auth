const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const app = express();
const PORT = 3000;

// Simple in-memory user store (replace with a database in production)
const users = {};

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Setup session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }  // Set to true in production with HTTPS
}));

// Register route with password hashing
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.status(400).send('User already exists');
  }

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = hashedPassword;
  res.send('Registration successful');
});

// Login route with password comparison
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const storedPassword = users[username];

  if (storedPassword && await bcrypt.compare(password, storedPassword)) {
    // Store session data
    req.session.user = username;
    return res.send('Login successful! Welcome back.');
  }
  res.status(401).send('Invalid credentials');
});

// Protected route (example)
app.get('/profile', (req, res) => {
  if (req.session.user) {
    res.send(`Welcome to your profile, ${req.session.user}!`);
  } else {
    res.status(401).send('Please log in first.');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
