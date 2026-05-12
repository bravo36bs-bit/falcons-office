require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

const SECRET = process.env.JWT_SECRET || 'falcons_secret';

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage });

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json({
        success: false,
        message: 'Missing fields'
      });
    }

    const [countRows] = await db.query(
      'SELECT COUNT(*) AS total FROM users'
    );

    

    const [existing] = await db.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      return res.json({
        success: false,
        message: 'Username already exists'
      });
    }

    const hashed = await bcrypt.hash(password, 10);

const [result] =
await db.query(
 'SELECT * FROM users'
);
      

        // هنا يجي كود إنشاء الحساب الأصلي
    
  
    await db.query(
      'INSERT INTO users (username, password, is_online) VALUES (?, ?, 0)',
      [username, hashed]
    );

    res.json({
      success: true
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false
    });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const [rows] = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const user = rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    await db.query(
      'UPDATE users SET is_online = 1 WHERE id = ?',
      [user.id]
    );

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username
      },
      SECRET,
      {
        expiresIn: '7d'
      }
    );

    io.emit('status_update');

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false
    });
  }
});

app.post('/api/send', (req, res) => {
    const { sender, message } = req.body;

    if (!sender || !message) {
        return res.status(400).json({
            error: 'Missing data'
        });
    }

    db.query(
        'INSERT INTO messages (sender, message) VALUES (?, ?)',
        [sender, message],
        (err) => {
            if (err) {
                console.log(err);
                return res.status(500).json({
                    error: 'Database error'
                });
            }

            res.json({
                success: true
            });
        }
    );
});









// GET MESSAGES


// FILE UPLOAD
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  console.log(req.session);
  res.json({
    path: `/uploads/${req.file.filename}`
  });
});

// SOCKET AUTH
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, SECRET);
    socket.user = decoded;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

// SOCKET EVENTS
io.on('connection', (socket) => {

 socket.on('send_message', async (data) => {

  try {

    await db.query(
      'INSERT INTO messages (sender, message, file) VALUES (?, ?, ?)',
  [socket.user.username, data.message || null, data.file || null]
    );

   const msg = {

  sender: socket.user.username,
  message:data.message || null,
file:data.file || null,
  created_at: new Date()

};

    io.emit('receive_message', msg);

  } catch (err) {

    console.log(err);

  }

});

  socket.on('disconnect', async () => {

    await db.query(
      'UPDATE users SET is_online = 0 WHERE id = ?',
      [socket.user.id]
    );

    io.emit('status_update');

  });

});


// جلب كل المستخدمين
app.get('/api/users', async (req, res) => {
  try {
    const [users] = await db.promise().query(
      'SELECT id, username FROM users'
    );

    res.json(users);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages', async (req, res) => {

  try {

    const [messages] = await db.query(
      'SELECT sender, message, file, created_at FROM messages ORDER BY created_at ASC'
    );

    res.json(messages);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      error: 'server error'
    });

  }

});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
