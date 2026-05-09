
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
  cors: {
    origin: '*'
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

const SECRET = process.env.JWT_SECRET;

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
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

function auth(req, res, next) {

  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {

    const decoded = jwt.verify(token, SECRET);

    req.user = decoded;

    next();

  } catch {

    return res.status(401).json({
      error: 'Invalid token'
    });

  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ================= REGISTER =================

app.post('/api/register', async (req, res) => {

  try {

    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Missing fields'
      });
    }

    const [countRows] = await db.query(
      'SELECT COUNT(*) AS total FROM users'
    );

    if (countRows[0].total >= 4) {
      return res.status(403).json({
        success: false,
        message: 'Registration closed'
      });
    }

    const [existing] = await db.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Username already exists'
      });
    }

    const hashed = await bcrypt.hash(password, 10);

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

// ================= LOGIN =================

app.post('/api/login', async (req, res) => {

  try {

    const { username, password } = req.body;

    const [rows] = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({
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
      return res.status(401).json({
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

// ================= FRIEND REQUEST =================

app.post('/api/send-request', auth, async (req, res) => {

  try {

    const { friendName } = req.body;

    const [friendRows] = await db.query(
      'SELECT id FROM users WHERE username = ?',
      [friendName]
    );

    if (friendRows.length === 0) {
      return res.json({
        success: false,
        error: 'User not found'
      });
    }

    const friendId = friendRows[0].id;

    await db.query(
      'INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)',
      [req.user.id, friendId]
    );

    io.emit('friend_request', {
      from: req.user.username
    });

    res.json({
      success: true
    });

  } catch (err) {

    console.log(err);

    res.json({
      success: false,
      error: 'Request failed'
    });

  }
});

// ================= GET REQUESTS =================

app.get('/api/friend-requests', auth, async (req, res) => {

  const [rows] = await db.query(
    `
    SELECT friend_requests.id, users.username
    FROM friend_requests
    JOIN users
    ON friend_requests.sender_id = users.id
    WHERE friend_requests.receiver_id = ?
    `,
    [req.user.id]
  );

  res.json(rows);
});

// ================= ACCEPT REQUEST =================

app.post('/api/accept-request', auth, async (req, res) => {

  try {

    const { requestId } = req.body;

    const [rows] = await db.query(
      'SELECT * FROM friend_requests WHERE id = ?',
      [requestId]
    );

    if (rows.length === 0) {
      return res.json({
        success: false
      });
    }

    const request = rows[0];

    await db.query(
      'INSERT INTO friends (user_id, friend_id) VALUES (?, ?)',
      [request.sender_id, request.receiver_id]
    );

    await db.query(
      'INSERT INTO friends (user_id, friend_id) VALUES (?, ?)',
      [request.receiver_id, request.sender_id]
    );

    await db.query(
      'DELETE FROM friend_requests WHERE id = ?',
      [requestId]
    );

    io.emit('friends_updated');

    res.json({
      success: true
    });

  } catch {

    res.json({
      success: false
    });

  }
});

// ================= FRIENDS =================

app.get('/api/friends', auth, async (req, res) => {

  const [rows] = await db.query(
    `
    SELECT users.id, users.username, users.is_online
    FROM friends
    JOIN users
    ON friends.friend_id = users.id
    WHERE friends.user_id = ?
    `,
    [req.user.id]
  );

  res.json(rows);
});

// ================= GET MESSAGES =================

app.get('/api/messages/:friendId', auth, async (req, res) => {

  const friendId = req.params.friendId;

  const [rows] = await db.query(
    `
    SELECT *
    FROM messages
    WHERE
    (sender_id = ? AND receiver_id = ?)
    OR
    (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at ASC
    `,
    [
      req.user.id,
      friendId,
      friendId,
      req.user.id
    ]
  );

  res.json(rows);
});

// ================= FILE UPLOAD =================

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {

  res.json({
    path: `/uploads/${req.file.filename}`
  });
});

// ================= SOCKET =================

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

io.on('connection', (socket) => {

  socket.on('send_message', async (data) => {

    const sender_id = socket.user.id;

    const { receiver_id, message } = data;

    const [result] = await db.query(
      `
      INSERT INTO messages
      (sender_id, receiver_id, message)
      VALUES (?, ?, ?)
      `,
      [sender_id, receiver_id, message]
    );

    const msg = {
      id: result.insertId,
      sender_id,
      receiver_id,
      message
    };

    io.emit('receive_message', msg);
  });

  socket.on('disconnect', async () => {

    await db.query(
      'UPDATE users SET is_online = 0 WHERE id = ?',
      [socket.user.id]
    );

    io.emit('status_update');
  });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});


