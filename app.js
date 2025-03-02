const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'test'
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
    db.query(query, [email, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'Email already exists' });
        }
        return res.status(500).json({ message: 'Error registering user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    res.status(500).json({ message: 'Error hashing password' });
  }
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error during login' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token });
  });
});

// Get account information
app.get('/account', authenticateToken, (req, res) => {
  const query = 'SELECT id, email, name, phone, description, picture_url, is_public FROM users WHERE id = ?';
  db.query(query, [req.user.userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching account information' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = results[0];
    
    // Fetch user's projects
    const projectQuery = 'SELECT p.name FROM projects p JOIN user_projects up ON p.id = up.project_id WHERE up.user_id = ?';
    db.query(projectQuery, [req.user.userId], (err, projectResults) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching user projects' });
      }
      user.projects = projectResults.map(project => project.name);
      res.json(user);
    });
  });
});

// Update account information
app.put('/account', authenticateToken, (req, res) => {
  const { email, password, name, phone, description, pictureUrl, isPublic } = req.body;
  
  let query = 'UPDATE users SET email = ?, name = ?, phone = ?, description = ?, picture_url = ?, is_public = ? WHERE id = ?';
  let params = [email, name, phone, description, pictureUrl, isPublic, req.user.userId];

  if (password) {
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error hashing password' });
      }
      query = 'UPDATE users SET email = ?, password = ?, name = ?, phone = ?, description = ?, picture_url = ?, is_public = ? WHERE id = ?';
      params = [email, hashedPassword, name, phone, description, pictureUrl, isPublic, req.user.userId];
      
      updateUser(query, params, res);
    });
  } else {
    updateUser(query, params, res);
  }
});

function updateUser(query, params, res) {
  db.query(query, params, (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error updating account' });
    }
    res.json({ message: 'Account updated successfully' });
  });
}

// Get public profiles
app.get('/public-profiles', (req, res) => {
  const query = 'SELECT id, name, description, picture_url FROM users WHERE is_public = TRUE';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching public profiles' });
    }
    res.json(results);
  });
});

// Admin: Add project to user
app.post('/admin/add-project', authenticateToken, (req, res) => {
  const { userId, projectName } = req.body;

  // Check if user is admin (you need to implement this logic)
  const adminCheckQuery = 'SELECT * FROM admins WHERE user_id = ?';
  db.query(adminCheckQuery, [req.user.userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(403).json({ message: 'Access denied. Admin only.' });
    }

    // Add project
    const addProjectQuery = 'INSERT INTO projects (name) VALUES (?)';
    db.query(addProjectQuery, [projectName], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Error adding project' });
      }

      const projectId = result.insertId;
      const linkProjectQuery = 'INSERT INTO user_projects (user_id, project_id) VALUES (?, ?)';
      db.query(linkProjectQuery, [userId, projectId], (err, result) => {
        if (err) {
          return res.status(500).json({ message: 'Error linking project to user' });
        }
        res.json({ message: 'Project added successfully' });
      });
    });
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
