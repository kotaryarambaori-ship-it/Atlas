const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  console.log('Database connected');
}
initDb().catch(err => console.error('DB error:', err.message));

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'atlas-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/db-test', async (req, res) => {
  try {
    const r = await pool.query('SELECT NOW()');
    res.send('Database connected: ' + r.rows[0].now);
  } catch (e) {
    res.status(500).send('DB error: ' + e.message);
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username.trim(), hash]
    );
    req.session.user = r.rows[0];
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(400).json({ error: 'Username already taken' });
    }
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (r.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.user = { id: user.id, username: user.username };
    res.json({ user: req.session.user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

app.get('/api/posts', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM posts ORDER BY created_at DESC LIMIT 100');
    res.json({ posts: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/posts', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Login required' });
    }
    const content = (req.body.content || '').trim();
    if (!content) {
      return res.status(400).json({ error: 'Content required' });
    }
    const r = await pool.query(
      'INSERT INTO posts (user_id, username, content) VALUES ($1, $2, $3) RETURNING *',
      [req.session.user.id, req.session.user.username, content]
    );
    res.json({ post: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log('Atlas running on port ' + PORT));
