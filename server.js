


require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET || 'falcons_secret_key';

// ===== MySQL Connection =====

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// ===== REGISTER =====

app.post('/api/register', async (req, res) => {

  const { username, password } = req.body;

  try {

    // نتأكد المستخدم مو موجود
    const [existing] = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {

      return res.status(400).json({
        error: 'Username already exists'
      });

    }

    // تشفير الباسوورد
    const hashedPassword =
      await bcrypt.hash(password, 10);

    // تخزين المستخدم
    await db.query(
      'INSERT INTO users(username,password) VALUES(?,?)',
      [username, hashedPassword]
    );

    res.json({
      success: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Server error'
    });

  }

});

// ===== LOGIN =====

app.post('/api/login', async (req, res) => {

  const { username, password } = req.body;

  try {

    const [rows] = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {

      return res.status(401).json({
        error: 'Invalid credentials'
      });

    }

    const user = rows[0];

    // مقارنة الباسوورد الحقيقي مع الهاش
    const match = await bcrypt.compare(
      password,
      user.password
    );

    if (!match) {

      return res.status(401).json({
        error: 'Invalid credentials'
      });

    }

    // إنشاء توكن
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

    res.json({
      token
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: 'Server error'
    });

  }

});

// ===== START SERVER =====

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

