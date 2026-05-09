
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

db.connect((err) => {
  if (err) {
    console.log('Database error:', err);
  } else {
    console.log('MySQL Connected');
  }
});


// ======================
// HOME
// ======================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// ======================
// REGISTER
// ======================

app.post('/api/register', async (req, res) => {

  try {

    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Missing data'
      });
    }

    db.query(
      'SELECT * FROM users WHERE username = ?',
      [username],
      async (err, result) => {

        if (err) {
          return res.status(500).json({
            success: false
          });
        }

        if (result.length > 0) {
          return res.status(400).json({
            success: false,
            message: 'User already exists'
          });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
          'INSERT INTO users (username, password, is_online) VALUES (?, ?, 0)',
          [username, hashedPassword],
          (err2) => {

            if (err2) {
              return res.status(500).json({
                success: false
              });
            }

            res.json({
              success: true
            });

          }
        );

      }
    );

  } catch (error) {

    res.status(500).json({
      success: false
    });

  }

});


// ======================
// LOGIN
// ======================

app.post('/api/login', (req, res) => {

  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, result) => {

      if (err) {
        return res.status(500).json({
          success: false
        });
      }

      if (result.length === 0) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const user = result[0];

      const match = await bcrypt.compare(
        password,
        user.password
      );

      if (!match) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      db.query(
        'UPDATE users SET is_online = 1 WHERE id = ?',
        [user.id]
      );

      res.json({
        success: true,
        id: user.id,
        username: user.username
      });

    }
  );

});


// ======================
// ADD FRIEND
// ======================

app.post('/api/add-friend', (req, res) => {

  const { user_id, friend_username } = req.body;

  db.query(
    'SELECT id FROM users WHERE username = ?',
    [friend_username],
    (err, result) => {

      if (err || result.length === 0) {

        return res.status(404).json({
          success: false,
          message: 'User not found'
        });

      }

      const friend_id = result[0].id;

      db.query(
        'INSERT INTO friends (user_id, friend_id) VALUES (?, ?)',
        [user_id, friend_id],
        (err2) => {

          if (err2) {

            return res.status(500).json({
              success: false
            });

          }

          res.json({
            success: true
          });

        }
      );

    }
  );

});


// ======================
// GET FRIENDS
// ======================

app.get('/api/friends/:id', (req, res) => {

  const userId = req.params.id;

  db.query(
    `
    SELECT users.id, users.username, users.is_online
    FROM friends
    JOIN users
    ON friends.friend_id = users.id
    WHERE friends.user_id = ?
    `,
    [userId],
    (err, result) => {

      if (err) {

        return res.status(500).json({
          success: false
        });

      }

      res.json(result);

    }
  );

});


// ======================
// SEND MESSAGE
// ======================

app.post('/api/send-message', (req, res) => {

  const {
    sender_id,
    receiver_id,
    message
  } = req.body;

  db.query(
    `
    INSERT INTO messages
    (sender_id, receiver_id, message)
    VALUES (?, ?, ?)
    `,
    [sender_id, receiver_id, message],
    (err) => {

      if (err) {

        return res.status(500).json({
          success: false
        });

      }

      res.json({
        success: true
      });

    }
  );

});


// ======================
// GET MESSAGES
// ======================

app.get('/api/messages/:user1/:user2', (req, res) => {

  const user1 = req.params.user1;
  const user2 = req.params.user2;

  db.query(
    `
    SELECT *
    FROM messages
    WHERE
    (sender_id = ? AND receiver_id = ?)
    OR
    (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at ASC
    `,
    [user1, user2, user2, user1],
    (err, result) => {

      if (err) {

        return res.status(500).json({
          success: false
        });

      }

      res.json(result);

    }
  );

});


// ======================
// LOGOUT
// ======================

app.post('/api/logout', (req, res) => {

  const { user_id } = req.body;

  db.query(
    'UPDATE users SET is_online = 0 WHERE id = ?',
    [user_id],
    () => {

      res.json({
        success: true
      });

    }
  );

});


// ======================
// START SERVER
// ======================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

