const crypto = require('crypto');
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
    "full_name TEXT", "email TEXT", "phone TEXT", "dob DATE",
    "role TEXT DEFAULT 'user'", "status TEXT DEFAULT 'active'",
    "updated_at TIMESTAMP DEFAULT NOW()",
    "bio TEXT", "location TEXT", "website TEXT"
  ];
  for (const c of cols) await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS ' + c);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users (lower(email)) WHERE email IS NOT NULL');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq ON users (lower(username))');

  await pool.query(`CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query('CREATE INDEX IF NOT EXISTS comments_post_idx ON comments (post_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (post_id, user_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (follower_id, following_id),
    CHECK (follower_id <> following_id))`);
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
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7 * 24 * 60 * 60 * 1000 }
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
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 60,
  message: { error: 'Too many actions. Slow down a little.' }
});
app.use('/api', (req, res, next) =>
  (req.method === 'GET' || req.path === '/login' || req.path === '/signup') ? next() : writeLimiter(req, res, next));

function publicUser(u) {
  return { id: u.id, username: u.username, full_name: u.full_name, email: u.email, role: u.role, created_at: u.created_at };
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
async function auth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  if (!r.rows.length || (r.rows[0].status && r.rows[0].status !== 'active'))
    return res.status(401).json({ error: 'Login required' });
  req.user = r.rows[0];
  next();
}

// ---------- Health ----------
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, phase: 2, db: 'connected' });
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
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (password.length > 100) return res.status(400).json({ error: 'Password too long' });
    if (password !== confirm) return res.status(400).json({ error: 'Passwords do not match' });
    const dup = await pool.query(
      'SELECT username, email FROM users WHERE lower(username)=lower($1) OR lower(email)=$2', [username, email]);
    if (dup.rows.length) {
      const sameUser = dup.rows.some(r => r.username.toLowerCase() === username.toLowerCase());
      return res.status(400).json({ error: sameUser ? 'Username already taken' : 'Email already registered' });
    }
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      `INSERT INTO users (username, password, full_name, email, phone, dob)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [username, hash, full_name, email, phone || null, dob || null]);
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
      'SELECT * FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($1) LIMIT 1', [id]);
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
  if (!req.session.userId) return res.json({ user: null });
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  if (!r.rows.length || (r.rows[0].status && r.rows[0].status !== 'active'))
    return req.session.destroy(() => res.json({ user: null }));
  res.json({ user: publicUser(r.rows[0]) });
});

app.post('/api/forgot', (req, res) => {
  res.status(501).json({
    error: process.env.SMTP_HOST
      ? 'Password reset will be added in a later phase.'
      : 'Password reset email is not configured yet. SMTP settings are required.'
  });
});

// ---------- Profile ----------
app.get('/api/users/:username', auth, async (req, res) => {
  const r = await pool.query(
    `SELECT u.id, u.username, u.full_name, u.bio, u.location, u.website, u.created_at,
      (SELECT COUNT(*) FROM posts p WHERE p.user_id=u.id)::int AS posts,
      (SELECT COUNT(*) FROM follows f WHERE f.following_id=u.id)::int AS followers,
      (SELECT COUNT(*) FROM follows f WHERE f.follower_id=u.id)::int AS following,
      EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=$2 AND f.following_id=u.id) AS is_following
     FROM users u WHERE lower(u.username)=lower($1) AND u.status='active'`,
    [req.params.username, req.user.id]);
  if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
  const u = r.rows[0];
  u.is_me = u.id === req.user.id;
  res.json({ user: u });
});

app.put('/api/profile', auth, async (req, res) => {
  const b = req.body || {};
  const full_name = String(b.full_name || '').trim();
  const bio = String(b.bio || '').trim();
  const location = String(b.location || '').trim();
  const website = String(b.website || '').trim();
  if (full_name.length < 2 || full_name.length > 80)
    return res.status(400).json({ error: 'Name must be 2 to 80 characters' });
  if (bio.length > 200) return res.status(400).json({ error: 'Bio max 200 characters' });
  if (location.length > 60) return res.status(400).json({ error: 'Location max 60 characters' });
  if (website && (website.length > 120 || !/^https?:\/\/[^\s]+$/i.test(website)))
    return res.status(400).json({ error: 'Website must start with http:// or https://' });
  await pool.query(
    'UPDATE users SET full_name=$1, bio=$2, location=$3, website=$4, updated_at=NOW() WHERE id=$5',
    [full_name, bio || null, location || null, website || null, req.user.id]);
  res.json({ ok: true });
});

app.post('/api/users/:username/follow', auth, async (req, res) => {
  const t = await pool.query("SELECT id FROM users WHERE lower(username)=lower($1) AND status='active'", [req.params.username]);
  if (!t.rows.length) return res.status(404).json({ error: 'User not found' });
  const target = t.rows[0].id;
  if (target === req.user.id) return res.status(400).json({ error: 'You cannot follow yourself' });
  const del = await pool.query('DELETE FROM follows WHERE follower_id=$1 AND following_id=$2', [req.user.id, target]);
  let following = false;
  if (del.rowCount === 0) {
    await pool.query('INSERT INTO follows (follower_id, following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, target]);
    following = true;
  }
  const c = await pool.query('SELECT COUNT(*)::int AS n FROM follows WHERE following_id=$1', [target]);
  res.json({ following, followers: c.rows[0].n });
});

// ---------- Posts ----------
const POST_SQL = `
  SELECT p.id, p.user_id, COALESCE(u.username, p.username) AS username, u.full_name,
    p.content, p.created_at,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id)::int AS likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id)::int AS comments,
    EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=$1) AS liked
  FROM posts p LEFT JOIN users u ON u.id=p.user_id `;

app.get('/api/posts', auth, async (req, res) => {
  const before = parseInt(req.query.before, 10) || null;
  const user = req.query.user ? String(req.query.user) : null;
  const r = await pool.query(
    POST_SQL + `WHERE ($2::int IS NULL OR p.id < $2) AND ($3::text IS NULL OR lower(u.username)=lower($3))
                ORDER BY p.id DESC LIMIT 20`,
    [req.user.id, before, user]);
  res.json({ posts: r.rows, me: req.user.id, admin: req.user.role === 'admin' });
});

app.post('/api/posts', auth, async (req, res) => {
  const content = String((req.body || {}).content || '').trim();
  if (!content) return res.status(400).json({ error: 'Write something first' });
  if (content.length > 1000) return res.status(400).json({ error: 'Post too long (max 1000)' });
  const r = await pool.query(
    'INSERT INTO posts (user_id, username, content) VALUES ($1,$2,$3) RETURNING id',
    [req.user.id, req.user.username, content]);
  res.json({ id: r.rows[0].id });
});

app.put('/api/posts/:id', auth, async (req, res) => {
  const content = String((req.body || {}).content || '').trim();
  if (!content) return res.status(400).json({ error: 'Post cannot be empty' });
  if (content.length > 1000) return res.status(400).json({ error: 'Post too long (max 1000)' });
  const r = await pool.query('UPDATE posts SET content=$1 WHERE id=$2 AND user_id=$3',
    [content, parseInt(req.params.id, 10) || 0, req.user.id]);
  if (!r.rowCount) return res.status(403).json({ error: 'You can edit only your own posts' });
  res.json({ ok: true });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  const isAdmin = req.user.role === 'admin';
  const r = await pool.query(
    isAdmin ? 'DELETE FROM posts WHERE id=$1' : 'DELETE FROM posts WHERE id=$1 AND user_id=$2',
    isAdmin ? [id] : [id, req.user.id]);
  if (!r.rowCount) return res.status(403).json({ error: 'You can delete only your own posts' });
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  const p = await pool.query('SELECT 1 FROM posts WHERE id=$1', [id]);
  if (!p.rows.length) return res.status(404).json({ error: 'Post not found' });
  const del = await pool.query('DELETE FROM likes WHERE post_id=$1 AND user_id=$2', [id, req.user.id]);
  let liked = false;
  if (del.rowCount === 0) {
    await pool.query('INSERT INTO likes (post_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, req.user.id]);
    liked = true;
  }
  const c = await pool.query('SELECT COUNT(*)::int AS n FROM likes WHERE post_id=$1', [id]);
  res.json({ liked, likes: c.rows[0].n });
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  const r = await pool.query(
    `SELECT c.id, c.user_id, c.content, c.created_at, u.username, u.full_name
     FROM comments c JOIN users u ON u.id=c.user_id
     WHERE c.post_id=$1 ORDER BY c.id ASC LIMIT 200`,
    [parseInt(req.params.id, 10) || 0]);
  res.json({ comments: r.rows, me: req.user.id });
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  const content = String((req.body || {}).content || '').trim();
  if (!content) return res.status(400).json({ error: 'Write a comment first' });
  if (content.length > 500) return res.status(400).json({ error: 'Comment too long (max 500)' });
  const p = await pool.query('SELECT 1 FROM posts WHERE id=$1', [id]);
  if (!p.rows.length) return res.status(404).json({ error: 'Post not found' });
  await pool.query('INSERT INTO comments (post_id, user_id, content) VALUES ($1,$2,$3)', [id, req.user.id, content]);
  res.json({ ok: true });
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  const r = await pool.query('DELETE FROM comments WHERE id=$1 AND user_id=$2',
    [parseInt(req.params.id, 10) || 0, req.user.id]);
  if (!r.rowCount) return res.status(403).json({ error: 'You can delete only your own comments' });
  res.json({ ok: true });
});

// ---------- Search ----------
app.get('/api/search', auth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2 || q.length > 50) return res.status(400).json({ error: 'Type 2 to 50 characters' });
  const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
  const users = await pool.query(
    `SELECT username, full_name, bio FROM users
     WHERE status='active' AND (username ILIKE $1 OR full_name ILIKE $1)
     ORDER BY username ASC LIMIT 20`, [like]);
  const posts = await pool.query(
    POST_SQL + 'WHERE p.content ILIKE $2 ORDER BY p.id DESC LIMIT 20', [req.user.id, like]);
  res.json({ users: users.rows, posts: posts.rows, me: req.user.id, admin: req.user.role === 'admin' });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});

app.listen(PORT, () => console.log('RINKU running on port ' + PORT));
