const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify({
      users: [],
      posts: [],
      messages: []
    }, null, 2)
  );
}

function readDB() {
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

function writeDB(db) {
  const tempFile = DATA_FILE + ".tmp";

  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
}

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "atlas.sid",
    secret: process.env.SESSION_SECRET || "change-this-secret-before-deployment",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  next();
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    bio: user.bio
  };
}

// Register
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();

    const displayName = String(req.body.displayName || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Username must be 3-20 characters (letters, numbers, underscores)."
      });
    }

    if (displayName.length < 2 || displayName.length > 40) {
      return res.status(400).json({
        error: "Display name must be 2-40 characters."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password must contain 8-72 characters."
      });
    }

    const db = readDB();

    if (db.users.some(user => user.username === username)) {
      return res.status(409).json({
        error: "Username already exists."
      });
    }

    const user = {
      id: require("crypto").randomUUID(),
      username,
      displayName,
      bio: "",
      passwordHash: await bcrypt.hash(password, 12)
    };

    db.users.push(user);
    writeDB(db);

    req.session.userId = user.id;

    res.status(201).json({
      success: true,
      user: publicUser(user)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const db = readDB();
    const user = db.users.find(item => item.username === username);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: "Could not create session."
        });
      }

      req.session.userId = user.id;

      res.json({
        success: true,
        user: publicUser(user)
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// Current user
app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  const db = readDB();
  const user = db.users.find(
    item => item.id === req.session.userId
  );

  res.json({
    user: user ? publicUser(user) : null
  });
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: "Logout failed."
      });
    }

    res.clearCookie("atlas.sid");

    res.json({ success: true });
  });
});

// List users
app.get("/api/users", requireLogin, (req, res) => {
  const db = readDB();

  res.json({
    users: db.users
      .filter(user => user.id !== req.session.userId)
      .map(publicUser)
  });
});

// Update profile
app.patch("/api/profile", requireLogin, (req, res) => {
  const displayName = String(req.body.displayName || "").trim();
  const bio = String(req.body.bio || "").trim();

  if (displayName.length < 2 || displayName.length > 40) {
    return res.status(400).json({
      error: "Display name must be 2-40 characters."
    });
  }

  if (bio.length > 160) {
    return res.status(400).json({
      error: "Bio cannot exceed 160 characters."
    });
  }

  const db = readDB();
  const user = db.users.find(
    item => item.id === req.session.userId
  );

  if (!user) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  user.displayName = displayName;
  user.bio = bio;

  writeDB(db);

  res.json({
    success: true,
    user: publicUser(user)
  });
});

// Get posts
app.get("/api/posts", requireLogin, (req, res) => {
  const db = readDB();

  const posts = db.posts
    .slice()
    .reverse()
    .map(post => {
      const author = db.users.find(
        user => user.id === post.userId
      );

      const original = post.originalPostId
        ? db.posts.find(item => item.id === post.originalPostId)
        : null;

      const originalAuthor = original
        ? db.users.find(user => user.id === original.userId)
        : null;

      return {
        ...post,
        author: author ? publicUser(author) : null,
        original: original
          ? {
              id: original.id,
              text: original.text,
              author: originalAuthor
                ? publicUser(originalAuthor)
                : null
            }
          : null
      };
    });

  res.json({ posts });
});

// Create post
app.post("/api/posts", requireLogin, (req, res) => {
  const text = String(req.body.text || "").trim();

  if (!text || text.length > 1000) {
    return res.status(400).json({
      error: "Post must contain 1-1000 characters."
    });
  }

  const db = readDB();

  const post = {
    id: require("crypto").randomUUID(),
    userId: req.session.userId,
    text,
    originalPostId: null,
    createdAt: new Date().toISOString()
  };

  db.posts.push(post);
  writeDB(db);

  res.status(201).json({
    success: true,
    post
  });
});

// Repost
app.post("/api/posts/:id/repost", requireLogin, (req, res) => {
  const db = readDB();

  const original = db.posts.find(
    post => post.id === req.params.id
  );

  if (!original) {
    return res.status(404).json({
      error: "Post not found."
    });
  }

  const alreadyReposted = db.posts.some(
    post =>
      post.userId === req.session.userId &&
      post.originalPostId === original.id
  );

  if (alreadyReposted) {
    return res.status(409).json({
      error: "You already reposted this post."
    });
  }

  const repost = {
    id: require("crypto").randomUUID(),
    userId: req.session.userId,
    text: "",
    originalPostId: original.id,
    createdAt: new Date().toISOString()
  };

  db.posts.push(repost);
  writeDB(db);

  res.status(201).json({
    success: true,
    repost
  });
});

// Get messages with a particular user
app.get("/api/messages/:userId", requireLogin, (req, res) => {
  const db = readDB();

  const otherUser = db.users.find(
    user => user.id === req.params.userId
  );

  if (!otherUser) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  const messages = db.messages.filter(
    message =>
      (message.from === req.session.userId &&
        message.to === otherUser.id) ||
      (message.from === otherUser.id &&
        message.to === req.session.userId)
  );

  res.json({
    messages: messages.map(message => ({
      ...message,
      sender: publicUser(
        db.users.find(user => user.id === message.from)
      )
    }))
  });
});

// Send message
app.post("/api/messages/:userId", requireLogin, (req, res) => {
  const text = String(req.body.text || "").trim();

  if (!text || text.length > 2000) {
    return res.status(400).json({
      error: "Message must contain 1-2000 characters."
    });
  }

  const db = readDB();

  const recipient = db.users.find(
    user => user.id === req.params.userId
  );

  if (!recipient || recipient.id === req.session.userId) {
    return res.status(400).json({
      error: "Invalid recipient."
    });
  }

  const message = {
    id: require("crypto").randomUUID(),
    from: req.session.userId,
    to: recipient.id,
    text,
    createdAt: new Date().toISOString()
  };

  db.messages.push(message);
  writeDB(db);

  res.status(201).json({
    success: true,
    message
  });
});

// API status
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    message: "Atlas server is running."
  });
});

// Frontend fallback
app.use((req, res, next) => {
  if (req.method !== "GET" || req.path.startsWith("/api/")) {
    return next();
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Internal server error."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Atlas running on port ${PORT}`);
});
