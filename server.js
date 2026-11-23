const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set in production.");
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "darkzone.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: "darkzone.sid",
  secret: process.env.SESSION_SECRET || "local-development-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false });
const postLimiter = rateLimit({ windowMs: 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}
function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id, username, email FROM users WHERE id = ?").get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: "سجّل الدخول أولاً." });
  next();
}

app.get("/api/me", (req, res) => res.json({ user: currentUser(req) }));

app.post("/api/register", authLimiter, async (req, res) => {
  const username = clean(req.body.username);
  const email = clean(req.body.email).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(username))
    return res.status(400).json({ error: "اسم المستخدم يجب أن يكون 3–20 حرفاً أو رقماً." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "اكتب بريداً إلكترونياً صحيحاً." });
  if (password.length < 10 || password.length > 72)
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون 10 أحرف على الأقل." });

  const hash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
      .run(username, email, hash);
    req.session.userId = result.lastInsertRowid;
    res.status(201).json({ user: currentUser(req) });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "اسم المستخدم أو البريد مستخدم بالفعل." });
    res.status(500).json({ error: "حدث خطأ غير متوقع." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة." });
  req.session.userId = user.id;
  res.json({ user: currentUser(req) });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("darkzone.sid");
    res.json({ ok: true });
  });
});

app.get("/api/posts", (req, res) => {
  const posts = db.prepare(`
    SELECT posts.id, posts.body, posts.created_at, users.username
    FROM posts JOIN users ON users.id = posts.user_id
    ORDER BY posts.id DESC LIMIT 50
  `).all();
  res.json({ posts });
});

app.post("/api/posts", requireAuth, postLimiter, (req, res) => {
  const body = clean(req.body.body);
  if (!body || body.length > 500) return res.status(400).json({ error: "المنشور يجب أن يكون بين 1 و500 حرف." });
  const result = db.prepare("INSERT INTO posts (user_id, body) VALUES (?, ?)")
    .run(req.session.userId, body);
  const post = db.prepare(`
    SELECT posts.id, posts.body, posts.created_at, users.username
    FROM posts JOIN users ON users.id = posts.user_id WHERE posts.id = ?
  `).get(result.lastInsertRowid);
  res.status(201).json({ post });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`DARKZONE running on port ${PORT}`));
