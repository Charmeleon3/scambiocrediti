/*
Webapp per gestione crediti tra utenti durante una festa.
Stack: Node.js (Express) + HTML/CSS/JS statico + SQLite (tutto gratuito)
*/

// === server.js ===
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = 3000;

// --- DB Setup ---
const db = new sqlite3.Database('./database.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    credits INTEGER DEFAULT 10
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    amount INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// --- Middlewares ---
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'festasegreta2025',
  resave: false,
  saveUninitialized: true
}));

// --- Auth Middleware ---
function authRequired(req, res, next) {
  if (!req.session.username) return res.redirect('/login.html');
  next();
}

// --- Routes ---
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.username = username;
      res.redirect('/dashboard.html');
    } else {
      res.redirect('/login.html?error=1');
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

app.get('/api/user', authRequired, (req, res) => {
  db.get('SELECT username, credits FROM users WHERE username = ?', [req.session.username], (err, user) => {
    res.json(user);
  });
});

app.get('/api/users', authRequired, (req, res) => {
  db.all('SELECT username FROM users WHERE username != ?', [req.session.username], (err, users) => {
    res.json(users);
  });
});

app.post('/api/transfer', authRequired, (req, res) => {
  const sender = req.session.username;
  const { receiver, amount, password } = req.body;
  const amt = parseInt(amount);

  db.get('SELECT * FROM users WHERE username = ?', [sender], async (err, senderUser) => {
    if (!senderUser || !(await bcrypt.compare(password, senderUser.password)) || senderUser.credits < amt) {
      return res.status(403).send('Operazione non valida');
    }

    db.run('UPDATE users SET credits = credits - ? WHERE username = ?', [amt, sender], (err) => {
      db.run('UPDATE users SET credits = credits + ? WHERE username = ?', [amt, receiver], (err) => {
        db.run('INSERT INTO transactions (sender, receiver, amount) VALUES (?, ?, ?)', [sender, receiver, amt]);
        res.redirect('/dashboard.html');
      });
    });
  });
});

app.listen(PORT, () => console.log(`Server avviato su http://localhost:${PORT}`));

// === add_user.js ===
const readline = require('readline');
const db2 = new sqlite3.Database('./database.sqlite');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('Username: ', username => {
  rl.question('Password: ', password => {
    bcrypt.hash(password, 10, (err, hash) => {
      db2.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], err => {
        if (err) return console.error('Errore:', err.message);
        console.log('Utente creato con successo!');
        rl.close();
        db2.close();
      });
    });
  });
});
