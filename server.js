  = ;
const path = require('path');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').toLowerCase();

let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  console.warn('WARNING: SESSION_SECRET not set. Using a temporary one.');
  SECRET = crypto.randomBytes(32).toString('hex');
}

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
  const cols = [
    "full_name TEXT",
    "email TEXT",
    "phone TEXT",
    "dob DATE",
    "role TEXT DEFAULT 'user'",
    "status TEXT DEFAULT 'active'",
    "updated_at TIMESTAMP DEFAULT NOW()"
  ];
  for (const c of cols) {
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS ' + c);
  }
  await pool.query(
    'CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users (lower(email)) WHERE email IS NOT NULL'
  );
  await pool.query(
    'CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq ON users (lower(username))'
  );
  console.log('Database ready');
}
initDb().catch(e => console.error('DB init error:', e.message));

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));
app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'rinku.sid',
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10,
  message: { error: 'Too many attempts. Try again in 15 minutes.' }
});
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, limit: 10,
  message: { error: 'Too many signups from this network. Try later.' }
});

function publicUser(u) {
  return {
    id: u.id, username: u.username, full_name: u.full_name,
    email: u.email, role: u.role, created_at: u.created_at
  };
}
function startSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.save(e => (e ? reject(e) : resolve()));
    });
  });
}
async function maybeMakeAdmin(user) {
  const hit =
    (ADMIN_EMAIL && user.email && user.email.toLowerCase() === ADMIN_EMAIL) ||
    (ADMIN_USERNAME && user.username.toLowerCase() === ADMIN_USERNAME);
  if (hit && user.role !== 'admin') {
    await pool.query("UPDATE users SET role='admin' WHERE id=$1", [user.id]);
    user.role = 'admin';
  }
  return user;
}

// ---------- Health ----------
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, phase: 1, db: 'connected' });
  } catch (e) {
    res.status(500).json({ ok: false, db: 'error' });
  }
});

// ---------- Auth ----------
app.get('/api/check-username', async (req, res) => {
  const u = String(req.query.u || '').trim();
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(u)) return res.json({ available: false, reason: 'invalid' });
  const r = await pool.query('SELECT 1 FROM users WHERE lower(username)=lower($1)', [u]);
  res.json({ available: r.rows.length === 0 });
});

app.post('/api/signup', signupLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const full_name = String(b.full_name || '').trim();
    const username = String(b.username || '').trim();
    const email = String(b.email || '').trim().toLowerCase();
    const phone = String(b.phone || '').trim();
    const dob = String(b.dob || '').trim();
    const password = String(b.password || '');
    const confirm = String(b.confirm || '');

    if (full_name.length < 2 || full_name.length > 80)
      return res.status(400).json({ error: 'Full name must be 2 to 80 characters' });
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username))
      return res.status(400).json({ error: 'Username: 3-30 letters, numbers or underscore' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 120)
      return res.status(400).json({ error: 'Enter a valid email address' });
    if (phone && !/^[0-9+\-\s]{7,20}$/.test(phone))
      return res.status(400).json({ error: 'Enter a valid phone number' });
    if (dob && !/^\d{4}-\d{2}-\d{2}$/.test(dob))
      return res.status(400).json({ error: 'Enter a valid date of birth' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (password.length > 100)
      return res.status(400).json({ error: 'Password too long' });
    if (password !== confirm)
      return res.status(400).json({ error: 'Passwords do not match' });

    const dup = await pool.query(
      'SELECT username, email FROM users WHERE lower(username)=lower($1) OR lower(email)=$2',
      [username, email]
    );
    if (dup.rows.length) {
      const sameUser = dup.rows.some(r => r.username.toLowerCase() === username.toLowerCase());
      return res.status(400).json({ error: sameUser ? 'Username already taken' : 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      `INSERT INTO users (username, password, full_name, email, phone, dob)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [username, hash, full_name, email, phone || null, dob || null]
    );
    const user = await maybeMakeAdmin(r.rows[0]);
    await startSession(req, user);
    res.json({ user: publicUser(user) });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username or email already used' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const id = String((req.body || {}).identifier || '').trim();
    const password = String((req.body || {}).password || '');
    if (!id || !password) return res.status(400).json({ error: 'Enter email/username and password' });
    const r = await pool.query(
      'SELECT * FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($1) LIMIT 1',
      [id]
    );
    const bad = { error: 'Invalid email/username or password' };
    if (!r.rows.length) return res.status(401).json(bad);
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json(bad);
    if (user.status && user.status !== 'active')
      return res.status(403).json({ error: 'This account is suspended' });
    await maybeMakeAdmin(user);
    await startSession(req, user);
    res.json({ user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('rinku.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', async (req, res) => {
  try {
    if (!req.session.userId) return res.json({ user: null });
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
    if (!r.rows.length || (r.rows[0].status && r.rows[0].status !== 'active')) {
      return req.session.destroy(() => res.json({ user: null }));
    }
    res.json({ user: publicUser(r.rows[0]) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/forgot', (req, res) => {
  if (!process.env.SMTP_HOST) {
    return res.status(501).json({
      error: 'Password reset email is not configured yet. SMTP settings are required.'
    });
  }
  res.status(501).json({ error: 'Password reset will be added in a later phase.' });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});

app.listen(PORT, () => console.log('RINKU running on port ' + PORT));
