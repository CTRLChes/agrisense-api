const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const db      = require('../db');

router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ status: 'error', message: 'Username and password are required' });
    }

    try {
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.json({ status: 'error', message: 'Invalid username or password' });
        }

        const user  = rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.json({ status: 'error', message: 'Invalid username or password' });
        }

        res.json({
            status:    'success',
            message:   'Login successful',
            user_id:   user.user_id,
            username:  user.username,
            full_name: user.full_name,
            role:      user.role
        });

    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

module.exports = router;
