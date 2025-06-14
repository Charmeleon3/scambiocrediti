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
    credits INTEGER DEFAULT 100
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
    if (!senderUser || senderUser.credits < amt) {
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

const ADMIN_PASSWORD = 'buciodeculo110';

// --- API: Aggiungi utente ---
app.post('/api/admin/adduser', express.json(), (req, res) => {
  const { adminpass, username, password } = req.body;
  if (adminpass !== ADMIN_PASSWORD) return res.status(403).send('Accesso negato');

  bcrypt.hash(password, 10, (err, hash) => {
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], err => {
      if (err) return res.status(400).send('Errore: ' + err.message);
      res.send('Utente aggiunto con successo!');
    });
  });
});

// --- API: Modifica crediti ---
app.post('/api/admin/modcredits', express.json(), (req, res) => {
  const { adminpass, username, amount } = req.body;
  if (adminpass !== ADMIN_PASSWORD) return res.status(403).send('Accesso negato');

  db.run('UPDATE users SET credits = credits + ? WHERE username = ?', [amount, username], function (err) {
    if (err || this.changes === 0) return res.status(400).send('Utente non trovato o errore');
    res.send('Crediti aggiornati!');
  });
});

// --- API: Classifica ---
app.post('/api/admin/leaderboard', express.json(), (req, res) => {
  const { adminpass } = req.body;
  if (adminpass !== ADMIN_PASSWORD) return res.status(403).send('Accesso negato');

  db.all('SELECT username, credits FROM users ORDER BY credits DESC', (err, rows) => {
    if (err) return res.status(500).send([]);
    res.json(rows);
  });
});

// --- Imposta crediti precisi a un utente ---
app.post('/api/admin/setcredits', express.json(), (req, res) => {
  const { adminpass, username, credits } = req.body;
  if (adminpass !== ADMIN_PASSWORD) return res.status(403).send('Accesso negato');

  db.run('UPDATE users SET credits = ? WHERE username = ?', [credits, username], function (err) {
    if (err || this.changes === 0) return res.status(400).send('Errore aggiornamento');
    res.send('Crediti aggiornati con successo');
  });
});

// --- Elimina un utente ---
app.post('/api/admin/deleteuser', express.json(), (req, res) => {
  const { adminpass, username } = req.body;
  if (adminpass !== ADMIN_PASSWORD) return res.status(403).send('Accesso negato');

  db.run('DELETE FROM users WHERE username = ?', [username], function (err) {
    if (err || this.changes === 0) return res.status(400).send('Utente non trovato');
    res.send('Utente eliminato');
  });
});
