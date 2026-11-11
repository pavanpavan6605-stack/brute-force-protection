require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
else app.set("trust proxy", false);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database(path.join(DATA_DIR, "app.sqlite"));
db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA foreign_keys = ON");
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS ip_security (
    ip TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    blocked_until INTEGER,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}

const MAX_ATTEMPTS = 5;
const BLOCK_MS = 24 * 60 * 60 * 1000;

function clientIp(req) {
  // req.ip is supplied by Express. Never accept an IP address from the browser.
  return String(req.ip || req.socket.remoteAddress || "unknown").replace(/^::ffff:/, "");
}

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR, table: "sessions" }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  name: "bfprotect.sid",
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000
  }
}));

// Same-origin check for state-changing API requests.
app.use("/api", (req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.get("origin")) {
    const origin = new URL(req.get("origin")).host;
    if (origin !== req.get("host")) return res.status(403).json({ error: "Request origin not allowed." });
  }
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login requests. Please wait and try again." }
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Administrator access required." });
  }
  next();
}

async function getIpState(ip) {
  return (await get("SELECT * FROM ip_security WHERE ip = ?", [ip])) ||
    { ip, failed_attempts: 0, blocked_until: null };
}
async function setFailedAttempt(ip) {
  const state = await getIpState(ip);
  const attempts = state.failed_attempts + 1;
  const blockedUntil = attempts >= MAX_ATTEMPTS ? Date.now() + BLOCK_MS : null;
  await run(
    `INSERT INTO ip_security (ip, failed_attempts, blocked_until, updated_at)
     VALUES (?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(ip) DO UPDATE SET
       failed_attempts = excluded.failed_attempts,
       blocked_until = excluded.blocked_until,
       updated_at = CURRENT_TIMESTAMP`,
    [ip, attempts, blockedUntil]
  );
  return { attempts, blockedUntil };
}
async function resetIp(ip) {
  await run(
    `INSERT INTO ip_security (ip, failed_attempts, blocked_until, updated_at)
     VALUES (?, 0, NULL, CURRENT_TIMESTAMP)
     ON CONFLICT(ip) DO UPDATE SET
       failed_attempts = 0, blocked_until = NULL, updated_at = CURRENT_TIMESTAMP`,
    [ip]
  );
}

app.get("/api/status", async (req, res, next) => {
  try {
    const ip = clientIp(req);
    const state = await getIpState(ip);
    const activeBlock = state.blocked_until && state.blocked_until > Date.now()
      ? state.blocked_until : null;
    if (state.blocked_until && !activeBlock) await resetIp(ip);
    res.json({
      ip,
      failedAttempts: activeBlock ? state.failed_attempts : (activeBlock === null && state.blocked_until ? 0 : state.failed_attempts),
      maxAttempts: MAX_ATTEMPTS,
      blockedUntil: activeBlock
    });
  } catch (e) { next(e); }
});

app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) {
      return res.status(400).json({ error: "User ID must be 3–30 characters and use letters, numbers, dot, underscore or hyphen." });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: "Password must be between 8 and 72 characters." });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash]);
    res.status(201).json({ message: "Account created. You can now log in." });
  } catch (e) {
    if (e.code === "SQLITE_CONSTRAINT") return res.status(409).json({ error: "That User ID is already registered." });
    next(e);
  }
});

app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const ip = clientIp(req);
    const now = Date.now();
    let state = await getIpState(ip);

    if (state.blocked_until && state.blocked_until > now) {
      return res.status(423).json({
        error: "Access denied. This IP address is blocked for 24 hours after five failed attempts.",
        blockedUntil: state.blocked_until,
        failedAttempts: state.failed_attempts
      });
    }
    if (state.blocked_until && state.blocked_until <= now) {
      await resetIp(ip);
      state = { failed_attempts: 0, blocked_until: null };
    }

    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!username || !password) return res.status(400).json({ error: "Enter both User ID and password." });

    const user = await get("SELECT id, username, password_hash, role FROM users WHERE username = ? COLLATE NOCASE", [username]);
    const valid = user && await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      const result = await setFailedAttempt(ip);
      const remaining = Math.max(0, MAX_ATTEMPTS - result.attempts);
      if (result.blockedUntil) {
        return res.status(423).json({
          error: "Brute-force activity detected. This IP address is blocked for 24 hours.",
          failedAttempts: result.attempts,
          blockedUntil: result.blockedUntil
        });
      }
      return res.status(401).json({
        error: "Incorrect User ID or password.",
        failedAttempts: result.attempts,
        remainingAttempts: remaining
      });
    }

    await resetIp(ip);
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: user.id, username: user.username, role: user.role };
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.json({ message: "Login successful.", user: req.session.user });
      });
    });
  } catch (e) { next(e); }
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user, ip: clientIp(req) });
});

app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("bfprotect.sid", {
      httpOnly: true, sameSite: "strict",
      secure: process.env.NODE_ENV === "production"
    });
    res.json({ message: "Logged out successfully." });
  });
});

app.get("/api/admin/overview", requireAdmin, async (req, res, next) => {
  try {
    const users = await all("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC");
    const blocked = await all(
      "SELECT ip, failed_attempts, blocked_until, updated_at FROM ip_security WHERE blocked_until > ? ORDER BY blocked_until DESC",
      [Date.now()]
    );
    res.json({ users, blocked });
  } catch (e) { next(e); }
});

app.get("/api/security", requireAuth, async (req, res, next) => {
  try {
    const state = await getIpState(clientIp(req));
    res.json({
      ip: clientIp(req),
      failedAttempts: state.blocked_until && state.blocked_until <= Date.now() ? 0 : state.failed_attempts,
      maxAttempts: MAX_ATTEMPTS,
      blockedUntil: state.blocked_until && state.blocked_until > Date.now() ? state.blocked_until : null,
      blockDurationHours: 24
    });
  } catch (e) { next(e); }
});

// Create/update the optional admin account from environment variables.
async function seedAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) return;
  if (password.length < 12) {
    console.warn("ADMIN_PASSWORD must be at least 12 characters. Admin account was not seeded.");
    return;
  }
  const hash = await bcrypt.hash(password, 12);
  await run(
    `INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')
     ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = 'admin'`,
    [username, hash]
  );
}

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "An internal server error occurred." });
});

seedAdmin().then(() => {
  app.listen(PORT, () => console.log(`Brute Force Protection running at http://localhost:${PORT}`));
}).catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
