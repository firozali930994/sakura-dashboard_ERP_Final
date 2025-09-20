import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import fs from 'fs';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Database setup
const db = new Database(path.join(__dirname, '../../data.db'));
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);
`);

// Seed roles and admin
const ensureSeed = () => {
  const getRole = db.prepare('SELECT id FROM roles WHERE name = ?');
  const insertRole = db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)');
  const adminRoles = ['admin', 'manager', 'staff'];
  const roleIds = {};
  for (const roleName of adminRoles) {
    insertRole.run(roleName);
    const role = getRole.get(roleName);
    roleIds[roleName] = role?.id;
  }

  const adminEmail = process.env.ADMIN_EMAIL || 'admin@sakura.local';
  const adminPass = process.env.ADMIN_PASSWORD || 'Admin@1234';
  const adminName = process.env.ADMIN_NAME || 'Admin';
  const adminRoleId = roleIds['admin'];

  const getUser = db.prepare('SELECT id FROM users WHERE email = ?');
  if (!getUser.get(adminEmail)) {
    const hash = bcrypt.hashSync(adminPass, 10);
    db.prepare('INSERT INTO users (name, email, password_hash, role_id) VALUES (?, ?, ?, ?)')
      .run(adminName, adminEmail, hash, adminRoleId);
  }
};

ensureSeed();

// Auth helpers
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_secret';

function generateToken(user) {
  return jwt.sign({ id: user.id, role_id: user.role_id }, JWT_SECRET, { expiresIn: '8h' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(roleNames) {
  return (req, res, next) => {
    try {
      const getRoleName = db.prepare('SELECT name FROM roles WHERE id = ?');
      const role = getRoleName.get(req.user.role_id);
      if (!role || !roleNames.includes(role.name)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    } catch (e) {
      return res.status(500).json({ error: 'Role check failed' });
    }
  };
}

// Routes
app.get('/health', (req, res) => res.json({ ok: true }));

// Auth
app.post('/api/auth/register', authMiddleware, requireRole(['admin']), (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  const roleRow = db.prepare('SELECT id FROM roles WHERE name = ?').get(role);
  if (!roleRow) return res.status(400).json({ error: 'Invalid role' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already exists' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (name, email, password_hash, role_id) VALUES (?, ?, ?, ?)')
    .run(name, email, hash, roleRow.id);
  return res.json({ id: info.lastInsertRowid, name, email, role });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user);
  const roleName = db.prepare('SELECT name FROM roles WHERE id = ?').get(user.role_id)?.name;
  return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: roleName } });
});

// Public signup (default role: staff)
app.post('/api/auth/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already exists' });
  const staffRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('staff');
  const roleId = staffRole?.id;
  if (!roleId) return res.status(500).json({ error: 'Role not configured' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (name, email, password_hash, role_id) VALUES (?, ?, ?, ?)')
    .run(name, email, hash, roleId);
  const user = { id: info.lastInsertRowid, name, email, role_id: roleId };
  const token = generateToken(user);
  const roleName = 'staff';
  return res.json({ token, user: { id: user.id, name, email, role: roleName } });
});

// Roles CRUD (admin only)
app.get('/api/roles', authMiddleware, requireRole(['admin']), (req, res) => {
  const roles = db.prepare('SELECT * FROM roles ORDER BY id').all();
  res.json(roles);
});

app.post('/api/roles', authMiddleware, requireRole(['admin']), (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const info = db.prepare('INSERT INTO roles (name) VALUES (?)').run(name);
    res.json({ id: info.lastInsertRowid, name });
  } catch (e) {
    res.status(409).json({ error: 'Role exists' });
  }
});

app.delete('/api/roles/:id', authMiddleware, requireRole(['admin']), (req, res) => {
  const info = db.prepare('DELETE FROM roles WHERE id = ?').run(Number(req.params.id));
  res.json({ deleted: info.changes });
});

// Users CRUD
app.get('/api/users', authMiddleware, requireRole(['admin', 'manager']), (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email, r.name AS role
    FROM users u JOIN roles r ON r.id = u.role_id
    ORDER BY u.id
  `).all();
  res.json(rows);
});

app.put('/api/users/:id', authMiddleware, requireRole(['admin', 'manager']), (req, res) => {
  const { name, role } = req.body;
  const roleRow = role ? db.prepare('SELECT id FROM roles WHERE name = ?').get(role) : null;
  const info = db.prepare('UPDATE users SET name = COALESCE(?, name), role_id = COALESCE(?, role_id) WHERE id = ?')
    .run(name ?? null, roleRow ? roleRow.id : null, Number(req.params.id));
  res.json({ updated: info.changes });
});

app.delete('/api/users/:id', authMiddleware, requireRole(['admin']), (req, res) => {
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(Number(req.params.id));
  res.json({ deleted: info.changes });
});

// File uploads setup
const uploadsDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.png';
    cb(null, `u_${req.user?.id || 'anon'}_${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });
app.use('/uploads', express.static(uploadsDir));

// Me profile endpoints
app.get('/api/me', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT id, name, email, role_id FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  const roleName = db.prepare('SELECT name FROM roles WHERE id = ?').get(row.role_id)?.name;
  res.json({ id: row.id, name: row.name, email: row.email, role: roleName });
});

app.put('/api/me', authMiddleware, upload.single('photo'), (req, res) => {
  const { name, email, password } = req.body;
  let photoPath = null;
  if (req.file) {
    photoPath = `/uploads/${req.file.filename}`;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const newHash = password ? bcrypt.hashSync(password, 10) : null;
  db.prepare(`UPDATE users SET 
    name = COALESCE(?, name),
    email = COALESCE(?, email),
    password_hash = COALESCE(?, password_hash)
    WHERE id = ?
  `).run(name ?? null, email ?? null, newHash ?? null, req.user.id);
  const updated = db.prepare('SELECT id, name, email, role_id FROM users WHERE id = ?').get(req.user.id);
  const roleName = db.prepare('SELECT name FROM roles WHERE id = ?').get(updated.role_id)?.name;
  res.json({ id: updated.id, name: updated.name, email: updated.email, role: roleName, photo: photoPath });
});

// Serve static frontend if needed
const portalDir = path.join(__dirname, '../../SakuraPortal');
app.use(express.static(portalDir));

// Serve index.html for root route
app.get('/', (req, res) => {
  res.sendFile(path.join(portalDir, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Sakura ERP backend running on http://localhost:${PORT}`);
});


