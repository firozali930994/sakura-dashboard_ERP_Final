import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
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

// Simple JSON database setup
const dbFile = path.join(__dirname, '../../data.json');
let db = { users: [], roles: [] };

// Load database
if (fs.existsSync(dbFile)) {
  db = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
} else {
  // Initialize with default data
  db = {
    users: [],
    roles: [
      { id: 1, name: 'admin' },
      { id: 2, name: 'staff' }
    ]
  };
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
}

// Create default admin user if none exists
const adminExists = db.users.some(user => user.role_id === 1);
if (!adminExists) {
  const adminUser = {
    id: 1,
    name: 'Admin',
    email: 'admin@sakura.com',
    password_hash: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password: "password"
    role_id: 1,
    photo: null,
    created_at: new Date().toISOString()
  };
  db.users.push(adminUser);
  saveDb();
  console.log('Default admin user created: admin@sakura.com / password');
}

// Helper functions
const saveDb = () => {
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
};

const findUser = (id) => db.users.find(u => u.id === id);
const findUserByEmail = (email) => db.users.find(u => u.email === email);
const findRole = (id) => db.roles.find(r => r.id === id);

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const userId = req.user?.id || 'anonymous';
    const ext = path.extname(file.originalname);
    cb(null, `u_${userId}_${Date.now()}${ext}`);
  }
});
const upload = multer({ storage: storage });

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    // Check if user already exists
    if (findUserByEmail(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = {
      id: db.users.length + 1,
      name,
      email,
      password_hash: hashedPassword,
      role_id: 2, // Default to staff
      photo: null,
      created_at: new Date().toISOString()
    };

    db.users.push(newUser);
    saveDb();

    // Generate token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'User created successfully',
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: findRole(newUser.role_id)?.name
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: findRole(user.role_id)?.name,
        photo: user.photo
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/me', authenticateToken, (req, res) => {
  const user = findUser(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    role: findRole(user.role_id)?.name,
    photo: user.photo
  });
});

app.put('/api/me', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const userId = req.user.id;
    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    const user = findUser(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user data
    if (name && name !== user.name) {
      user.name = name;
    }
    if (email && email !== user.email) {
      user.email = email;
    }
    if (password) {
      user.password_hash = await bcrypt.hash(password, 10);
    }
    if (photoPath) {
      user.photo = photoPath;
    }

    saveDb();

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: findRole(user.role_id)?.name,
        photo: user.photo
      },
      photo: user.photo
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Serve uploads only (no frontend files)
app.use('/uploads', express.static(uploadsDir));

// API-only response for root route
app.get('/', (req, res) => {
  res.json({
    message: 'Sakura ERP Backend API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth/login, /api/auth/signup',
      profile: '/api/me',
      uploads: '/uploads'
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Sakura ERP backend running on http://localhost:${PORT}`);
});
