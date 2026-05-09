require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const rateLimit = require('express-rate-limit');
const xss = require('xss');
const multer = require('multer');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(express.json());
app.use(cors());

app.use(express.static('public'));
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});

app.use(limiter);



const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
  ssl: {
    rejectUnauthorized: false
  }
});
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Connected to Aiven MySQL');
    connection.release();
  }
});

const onlineUsers = {};
const storage = multer.diskStorage({

  destination: (req, file, cb) => {

    cb(null, 'public/uploads');

  },

  filename: (req, file, cb) => {

    cb(
      null,
      Date.now() +
      path.extname(file.originalname)
    );

  }

});

const upload = multer({
  storage
});
function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ error: 'Unauthorized' });

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

function initDB() {
  db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE,
      password VARCHAR(255),
      is_online BOOLEAN DEFAULT 0
    )
  `);

  db.query(`
    CREATE TABLE IF NOT EXISTS friends (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      friend_id INT
    )
  `);

  db.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      sender_id INT,
      receiver_id INT,
      message TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

initDB();

app.post('/api/register', async (req, res) => {
  try {
    const username = xss(req.body.username);
    const password = req.body.password;

  db.query(
  'SELECT COUNT(*) as total FROM users',
  async (err, result) => {

    if (result[0].total >= 4) {

      return res.status(403).json({
        error: 'Maximum users reached'
      });

    }

    const hash =
      await bcrypt.hash(password, 12);

    db.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hash],
      err => {

        if (err)
          return res.status(400).json({
            error: 'Username already exists'
          });

        res.json({
          success: true
        });

      }
    );

  }
);
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const username = xss(req.body.username);
  const password = req.body.password;

  db.query(
    'SELECT * FROM users WHERE username=?',
    [username],
    async (err, results) => {
      if (!results.length)
        return res.status(401).json({ error: 'Invalid credentials' });

      const user = results[0];

      const valid =
await bcrypt.compare(
  password,
  user.password
);

      if (!valid)
        return res.status(401).json({ error: 'Invalid credentials' });

      const token = jwt.sign(
        {
          id: user.id,
          username: user.username
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username
        }
      });
    }
  );
});

app.get('/api/friends', auth, (req, res) => {
  db.query(
    `
    SELECT users.id, users.username, users.is_online
    FROM friends
    JOIN users ON users.id = friends.friend_id
    WHERE friends.user_id=?
    `,
    [req.user.id],
    (err, results) => {
      res.json(results);
    }
  );
});

app.post('/api/send-request', auth, (req, res) => {
  const friendName = xss(req.body.friendName);

  db.query(
    'SELECT * FROM users WHERE username=?',
    [friendName],
    (err, results) => {

      if (!results.length)
        return res.status(404).json({
          error: 'User not found'
        });

      const receiver = results[0];

      if (receiver.id === req.user.id)
        return res.status(400).json({
          error: 'Cannot add yourself'
        });

      db.query(
        `
        SELECT * FROM friend_requests
        WHERE sender_id=? AND receiver_id=?
        AND status='pending'
        `,
        [req.user.id, receiver.id],
        (err, exists) => {

          if (exists.length)
            return res.status(400).json({
              error: 'Request already sent'
            });

          db.query(
            `
            INSERT INTO friend_requests
            (sender_id, receiver_id)
            VALUES (?, ?)
            `,
            [req.user.id, receiver.id],
            (err, result) => {

              if (onlineUsers[receiver.id]) {

                io.to(
                  onlineUsers[receiver.id]
                ).emit('friend_request', {
                  from: req.user.username,
                  sender_id: req.user.id
                });

              }

              res.json({
                success: true
              });

            }
          );

        }
      );

    }
  );
});
app.get('/api/friend-requests', auth, (req, res) => {

  db.query(
    `
    SELECT
      friend_requests.id,
      users.username,
      users.id as user_id
    FROM friend_requests
    JOIN users
    ON users.id = friend_requests.sender_id
    WHERE receiver_id=?
    AND status='pending'
    `,
    [req.user.id],
    (err, results) => {

      res.json(results);

    }
  );

});
app.post('/api/accept-request', auth, (req, res) => {

  const requestId = req.body.requestId;

  db.query(
    'SELECT * FROM friend_requests WHERE id=?',
    [requestId],
    (err, results) => {

      if (!results.length)
        return res.status(404).json({
          error: 'Request not found'
        });

      const request = results[0];

      db.query(
        `
        UPDATE friend_requests
        SET status='accepted'
        WHERE id=?
        `,
        [requestId]
      );

      db.query(
        `
        INSERT INTO friends
        (user_id, friend_id)
        VALUES (?, ?)
        `,
        [request.sender_id, request.receiver_id]
      );

      db.query(
        `
        INSERT INTO friends
        (user_id, friend_id)
        VALUES (?, ?)
        `,
        [request.receiver_id, request.sender_id]
      );

      io.emit('friends_updated');

      res.json({
        success: true
      });

    }
  );

});
app.post(
  '/api/upload',
  auth,
  upload.single('file'),
  (req, res) => {

    res.json({
      file: req.file.filename,
      path: `/uploads/${req.file.filename}`
    });

  }
);

app.get('/api/messages/:friendId', auth, (req, res) => {
  const friendId = req.params.friendId;

  db.query(
    `
    SELECT * FROM messages
    WHERE
    (sender_id=? AND receiver_id=?)
    OR
    (sender_id=? AND receiver_id=?)
    ORDER BY created_at ASC
    `,
    [req.user.id, friendId, friendId, req.user.id],
    (err, results) => {
      res.json(results);
    }
  );
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    socket.user = decoded;
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', socket => {
  const userId = socket.user.id;

  onlineUsers[userId] = socket.id;

  db.query('UPDATE users SET is_online=1 WHERE id=?', [userId]);

  io.emit('status_update', {
    userId,
    is_online: true
  });

  socket.on('send_message', data => {
    const clean = xss(data.message);

    db.query(
      'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
      [userId, data.receiver_id, clean],
      (err, result) => {
        const payload = {
          id: result.insertId,
          sender_id: userId,
          receiver_id: data.receiver_id,
          message: clean,
          created_at: new Date()
        };

        socket.emit('receive_message', payload);

        if (onlineUsers[data.receiver_id]) {
          io.to(onlineUsers[data.receiver_id]).emit('receive_message', payload);
        }
      }
    );
  });

  socket.on('disconnect', () => {
    delete onlineUsers[userId];

    db.query('UPDATE users SET is_online=0 WHERE id=?', [userId]);

    io.emit('status_update', {
      userId,
      is_online: false
    });
  });
});

const PORT =
process.env.PORT || 5000;

server.listen(PORT,()=>{
  console.log(
    `Falcons Running ${PORT}`
  );
});