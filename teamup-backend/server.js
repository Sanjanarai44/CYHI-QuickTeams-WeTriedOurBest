const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3001;

// Middleware
// Enable CORS for all origins (for development)
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Initialize SQLite database
const dbPath = path.join(__dirname, 'teamup.db');
const db = new sqlite3.Database(dbPath);

// Create tables if they don't exist
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Profiles table
  db.run(`CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    name TEXT,
    age INTEGER,
    quality TEXT,
    location TEXT,
    qualification TEXT,
    domain TEXT,
    skillset TEXT,
    bio TEXT,
    tags TEXT,
    photo_path TEXT,
    availability INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Teams table
  db.run(`CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    size INTEGER,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id)
  )`);

  // Team members table
  db.run(`CREATE TABLE IF NOT EXISTS team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER,
    user_id INTEGER,
    status TEXT DEFAULT 'pending',
    joined_at DATETIME,
    FOREIGN KEY(team_id) REFERENCES teams(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(team_id, user_id)
  )`);

  // Team invitations table
  db.run(`CREATE TABLE IF NOT EXISTS team_invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER,
    inviter_id INTEGER,
    invitee_id INTEGER,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(team_id) REFERENCES teams(id),
    FOREIGN KEY(inviter_id) REFERENCES users(id),
    FOREIGN KEY(invitee_id) REFERENCES users(id),
    UNIQUE(team_id, invitee_id)
  )`);
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = 'uploads/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// API Routes

// Root API endpoint
app.get('/api', (req, res) => {
  res.json({ 
    message: 'TeamUp API is working!',
    endpoints: [
      'POST /api/register',
      'POST /api/login',
      'GET /api/profile/:userId',
      'GET /api/profile?userId=',
      'POST /api/profile',
      'GET /api/users',
      'PUT /api/users/:userId/availability',
      'POST /api/teams',
      'GET /api/users/:userId/teams',
      'GET /api/teams/:teamId/members',
      'GET /api/users/:userId/invitations',
      'POST /api/invitations/:invitationId/respond',
      'GET /api/admin/users',
      'GET /api/admin/users/:id'
    ]
  });
});

// Admin endpoint to view all users (for development only)
app.get('/api/admin/users', (req, res) => {
  db.all(`
      SELECT u.*, p.name, p.domain, p.skillset 
      FROM users u 
      LEFT JOIN profiles p ON u.id = p.user_id
  `, (err, rows) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      res.json(rows);
  });
});

// Get specific user by ID
app.get('/api/admin/users/:id', (req, res) => {
  const userId = req.params.id;
  
  db.get(`
      SELECT u.*, p.* 
      FROM users u 
      LEFT JOIN profiles p ON u.id = p.user_id 
      WHERE u.id = ?
  `, [userId], (err, row) => {
      if (err) {
          return res.status(500).json({ error: err.message });
      }
      if (!row) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.json(row);
  });
});

// User registration
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  try {
    // Check if username or email already exists
    db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (row) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Insert new user
      db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
        [username, email, hashedPassword], 
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          res.json({ 
            id: this.lastID, 
            username, 
            email,
            message: 'Registration successful' 
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Return user data (without password)
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  });
});

// Get user profile
app.get('/api/profile/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.get(`
    SELECT p.*, u.username, u.email 
    FROM profiles p 
    JOIN users u ON p.user_id = u.id 
    WHERE p.user_id = ?
  `, [userId], (err, profile) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Parse tags from JSON string
    if (profile.tags) {
      try {
        profile.tags = JSON.parse(profile.tags);
      } catch (e) {
        profile.tags = [];
      }
    } else {
      profile.tags = [];
    }
    
    res.json(profile);
  });
});

// Get current user profile
app.get('/api/profile', (req, res) => {
  const userId = req.query.userId;
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  
  db.get(`
    SELECT p.*, u.username, u.email 
    FROM profiles p 
    JOIN users u ON p.user_id = u.id 
    WHERE p.user_id = ?
  `, [userId], (err, profile) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Parse tags from JSON string
    if (profile.tags) {
      try {
        profile.tags = JSON.parse(profile.tags);
      } catch (e) {
        profile.tags = [];
      }
    } else {
      profile.tags = [];
    }
    
    res.json(profile);
  });
});

// Save/update user profile
app.post('/api/profile', upload.single('photo'), (req, res) => {
  const {
    userId, name, age, quality, location, qualification, 
    domain, skillset, bio, tags
  } = req.body;
  
  let photoPath = null;
  if (req.file) {
    photoPath = `/uploads/${req.file.filename}`;
  }
  
  // Check if profile already exists
  db.get('SELECT id FROM profiles WHERE user_id = ?', [userId], (err, existingProfile) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (existingProfile) {
      // Update existing profile
      let query, params;
      
      if (photoPath) {
        query = `
          UPDATE profiles 
          SET name = ?, age = ?, quality = ?, location = ?, qualification = ?, 
              domain = ?, skillset = ?, bio = ?, tags = ?, photo_path = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE user_id = ?
        `;
        params = [name, age, quality, location, qualification, domain, skillset, bio, tags, photoPath, userId];
      } else {
        query = `
          UPDATE profiles 
          SET name = ?, age = ?, quality = ?, location = ?, qualification = ?, 
              domain = ?, skillset = ?, bio = ?, tags = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE user_id = ?
        `;
        params = [name, age, quality, location, qualification, domain, skillset, bio, tags, userId];
      }
      
      db.run(query, params, function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        res.json({ message: 'Profile updated successfully' });
      });
    } else {
      // Create new profile
      db.run(`
        INSERT INTO profiles 
        (user_id, name, age, quality, location, qualification, domain, skillset, bio, tags, photo_path) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [userId, name, age, quality, location, qualification, domain, skillset, bio, tags, photoPath], 
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        res.json({ message: 'Profile created successfully' });
      });
    }
  });
});

// Get all users for matching (excluding current user)
app.get('/api/users', (req, res) => {
  const currentUserId = req.query.current_user_id;
  
  if (!currentUserId) {
    return res.status(400).json({ error: 'current_user_id parameter is required' });
  }
  
  db.all(`
    SELECT u.id, u.username, u.email, 
           p.name, p.age, p.quality, p.location, p.qualification, 
           p.domain, p.skillset, p.bio, p.tags, p.photo_path, p.availability
    FROM users u
    LEFT JOIN profiles p ON u.id = p.user_id
    WHERE u.id != ?
  `, [currentUserId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    // Process the results
    const users = rows.map(user => ({
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name || user.username,
      age: user.age,
      quality: user.quality,
      location: user.location,
      qualification: user.qualification,
      domain: user.domain,
      skillset: user.skillset,
      bio: user.bio,
      tags: user.tags ? JSON.parse(user.tags) : [],
      avatar: user.photo_path || `https://via.placeholder.com/100?text=${user.username.charAt(0).toUpperCase()}`,
      available: user.availability === 1
    }));
    
    res.json(users);
  });
});

// Update user availability
app.put('/api/users/:userId/availability', (req, res) => {
  const userId = req.params.userId;
  const { available } = req.body;
  
  db.run(
    'UPDATE profiles SET availability = ? WHERE user_id = ?',
    [available ? 1 : 0, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Availability updated successfully' });
    }
  );
});

// Create a team
app.post('/api/teams', (req, res) => {
  const { name, size, created_by, members } = req.body;
  
  db.run(
    'INSERT INTO teams (name, size, created_by) VALUES (?, ?, ?)',
    [name, size, created_by],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      const teamId = this.lastID;
      
      // Add team members
      const stmt = db.prepare(
        'INSERT INTO team_members (team_id, user_id, status, joined_at) VALUES (?, ?, ?, CASE WHEN ? = ? THEN CURRENT_TIMESTAMP ELSE NULL END)'
      );
      
      members.forEach(userId => {
        const status = userId === created_by ? 'accepted' : 'pending';
        stmt.run([teamId, userId, status, userId, created_by]);
      });
      
      stmt.finalize();
      
      res.json({ id: teamId, message: 'Team created successfully' });
    }
  );
});

// Get user's teams
app.get('/api/users/:userId/teams', (req, res) => {
  const userId = req.params.userId;
  
  db.all(`
    SELECT t.*, tm.status, tm.joined_at
    FROM teams t
    JOIN team_members tm ON t.id = tm.team_id
    WHERE tm.user_id = ? AND tm.status = 'accepted'
    ORDER BY tm.joined_at DESC
  `, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    res.json(rows);
  });
});

// Get team members
app.get('/api/teams/:teamId/members', (req, res) => {
  const teamId = req.params.teamId;
  
  db.all(`
    SELECT u.id, u.username, p.name, p.photo_path, tm.status, tm.joined_at
    FROM team_members tm
    JOIN users u ON tm.user_id = u.id
    LEFT JOIN profiles p ON u.id = p.user_id
    WHERE tm.team_id = ? AND tm.status = 'accepted'
  `, [teamId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    const members = rows.map(member => ({
      id: member.id,
      username: member.username,
      name: member.name || member.username,
      avatar: member.photo_path || `https://via.placeholder.com/100?text=${member.username.charAt(0).toUpperCase()}`,
      status: member.status,
      joined_at: member.joined_at
    }));
    
    res.json(members);
  });
});

// Get user's team invitations
app.get('/api/users/:userId/invitations', (req, res) => {
  const userId = req.params.userId;
  
  db.all(`
    SELECT ti.*, t.name as team_name, u.username as inviter_username, p.name as inviter_name
    FROM team_invitations ti
    JOIN teams t ON ti.team_id = t.id
    JOIN users u ON ti.inviter_id = u.id
    LEFT JOIN profiles p ON u.id = p.user_id
    WHERE ti.invitee_id = ? AND ti.status = 'pending'
  `, [userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    res.json(rows);
  });
});

// Send team invitation
app.post('/api/invitations', (req, res) => {
  const { team_id, inviter_id, invitee_id } = req.body;
  
  // Check if invitation already exists
  db.get('SELECT id FROM team_invitations WHERE team_id = ? AND invitee_id = ?', 
    [team_id, invitee_id], (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (row) {
        return res.status(400).json({ error: 'Invitation already sent' });
      }
      
      // Create new invitation
      db.run('INSERT INTO team_invitations (team_id, inviter_id, invitee_id) VALUES (?, ?, ?)',
        [team_id, inviter_id, invitee_id], function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          res.json({ id: this.lastID, message: 'Invitation sent successfully' });
        }
      );
    }
  );
});

// Respond to team invitation
app.post('/api/invitations/:invitationId/respond', (req, res) => {
  const invitationId = req.params.invitationId;
  const { accept } = req.body;
  
  db.get('SELECT * FROM team_invitations WHERE id = ?', [invitationId], (err, invitation) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!invitation) {
      return res.status(404).json({ error: 'Invitation not found' });
    }
    
    if (accept) {
      // Accept invitation - add user to team
      db.run(
        'INSERT INTO team_members (team_id, user_id, status, joined_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
        [invitation.team_id, invitation.invitee_id, 'accepted'],
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          // Update invitation status
          db.run(
            'UPDATE team_invitations SET status = ? WHERE id = ?',
            ['accepted', invitationId],
            function(err) {
              if (err) {
                return res.status(500).json({ error: err.message });
              }
              
              res.json({ message: 'Invitation accepted successfully' });
            }
          );
        }
      );
    } else {
      // Reject invitation
      db.run(
        'UPDATE team_invitations SET status = ? WHERE id = ?',
        ['rejected', invitationId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          
          res.json({ message: 'Invitation rejected successfully' });
        }
      );
    }
  });
});

// Update user availability
app.put('/api/users/:userId/availability', (req, res) => {
  const userId = req.params.userId;
  const { available } = req.body;
  
  db.run(
    'UPDATE profiles SET availability = ? WHERE user_id = ?',
    [available ? 1 : 0, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Availability updated successfully' });
    }
  );
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
  }
  res.status(500).json({ error: error.message });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
  console.log(`Admin endpoint: http://localhost:${PORT}/api/admin/users`);
});