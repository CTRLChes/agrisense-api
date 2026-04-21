const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const db       = require('../db');

router.post('/register', async (req, res) => {
    const { username, email, password, full_name } = req.body;

    if (!username || !email || !password) {
        return res.json({ status: 'error', message: 'Username, email and password are required' });
    }

    if (password.length < 4) {
        return res.json({ status: 'error', message: 'Password must be at least 4 characters' });
    }

    try {
        const hashed = await bcrypt.hash(password, 10);

        await db.execute(
            'INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)',
            [username, email, hashed, full_name || username, 'general_user']
        );

        res.json({ status: 'success', message: 'Account created successfully' });

    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.json({ status: 'error', message: 'Username or email already exists' });
        } else {
            res.json({ status: 'error', message: 'Server error: ' + err.message });
        }
    }
});

module.exports = router;