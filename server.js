const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').toLowerCase();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages (sender_id, receiver_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS contact_messages (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW())`);
  console.log('Database ready');
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

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Login required' });
  next();
}
function isAdmin(req) {
  return !!(req.session.user && ADMIN_USERNAME &&
    req.session.user.username.toLowerCase() === ADMIN_USERNAME);
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ---------- AUTH ----------
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    if (username.trim().length > 40 || password.length < 4) {
      return res.status(400).json({ error: 'Username max 40, password min 4 characters' });
    }
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username.trim(), hash]
    );
    req.session.user = r.rows[0];
    res.json({ user: r.rows[0], admin: isAdmin(req) });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already taken' });
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
    const ok = await bcrypt.compare(password || '', user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });
    req.session.user = { id: user.id, username: user.username };
    res.json({ user: req.session.user, admin: isAdmin(req) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null, admin: isAdmin(req) });
});

// ---------- CONTACT (visitors, no login needed) ----------
const hits = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < 60000);
  if (list.length >= 5) {
    return res.status(429).json({ error: 'Too many messages. Try again in a minute.' });
  }
  list.push(now);
  hits.set(ip, list);
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, list] of hits) {
    if (!list.some(t => now - t < 60000)) hits.delete(ip);
  }
}, 60000);

app.post('/api/contact', rateLimit, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const message = (req.body.message || '').trim();
    if (!name || name.length > 100) {
      return res.status(400).json({ error: 'Name required (max 100 characters)' });
    }
    if (!message) return res.status(400).json({ error: 'Message is empty' });
    if (message.length > 1000) {
      return res.status(400).json({ error: 'Message too long (max 1000)' });
    }
    await pool.query(
      'INSERT INTO contact_messages (name, message) VALUES ($1, $2)',
      [name, message]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- ADMIN ----------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, name, message, created_at FROM contact_messages ORDER BY id DESC LIMIT 500'
    );
    res.json({ messages: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- POSTS ----------
app.get('/api/posts', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM posts ORDER BY created_at DESC LIMIT 100');
    res.json({ posts: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/posts', requireLogin, async (req, res) => {
  try {
    const content = (req.body.content || '').trim();
    if (!content) return res.status(400).json({ error: 'Content required' });
    const r = await pool.query(
      'INSERT INTO posts (user_id, username, content) VALUES ($1, $2, $3) RETURNING *',
      [req.session.user.id, req.session.user.username, content]
    );
    res.json({ post: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- CHAT ----------
app.get('/api/users', requireLogin, async (req, res) => {
  try {
    const me = req.session.user.id;
    const r = await pool.query(
      `SELECT u.id, u.username,
        (SELECT COUNT(*) FROM messages m
          WHERE m.sender_id = u.id AND m.receiver_id = $1 AND m.is_read = false)::int AS unread
       FROM users u WHERE u.id <> $1 ORDER BY u.username ASC`,
      [me]
    );
    res.json({ users: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/messages/:userId', requireLogin, async (req, res) => {
  try {
    const me = req.session.user.id;
    const other = parseInt(req.params.userId, 10);
    if (!other) return res.status(400).json({ error: 'Invalid user' });
    await pool.query(
      'UPDATE messages SET is_read = true WHERE sender_id = $1 AND receiver_id = $2 AND is_read = false',
      [other, me]
    );
    const r = await pool.query(
      `SELECT id, sender_id, receiver_id, content, created_at FROM (
         SELECT * FROM messages
         WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
         ORDER BY id DESC LIMIT 200
       ) t ORDER BY id ASC`,
      [me, other]
    );
    res.json({ messages: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/messages', requireLogin, async (req, res) => {
  try {
    const me = req.session.user.id;
    const receiver = parseInt(req.body.receiver_id, 10);
    const content = (req.body.content || '').trim();
    if (!receiver) return res.status(400).json({ error: 'Receiver required' });
    if (receiver === me) return res.status(400).json({ error: 'You cannot message yourself' });
    if (!content) return res.status(400).json({ error: 'Message is empty' });
    if (content.length > 1000) return res.status(400).json({ error: 'Message too long (max 1000)' });
    const exists = await pool.query('SELECT id FROM users WHERE id = $1', [receiver]);
    if (exists.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const r = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING id, sender_id, receiver_id, content, created_at',
      [me, receiver, content]
    );
    res.json({ message: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log('Atlas running on port ' + PORT));
