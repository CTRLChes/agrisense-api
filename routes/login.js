const express = require('express');
const router  = express.Router();
const bcrypt   = require('bcryptjs');
const db       = require('../db');

router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({
            success: false,
            message: 'Username and password are required'
        });
    }

    try {
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const user = rows[0];

        // 🔒 check password
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // 🚨 IMPORTANT: suspension check
        if (user.suspended === 1) {
            return res.json({
                success: false,
                message: 'Account suspended',
                suspended: 1
            });
        }

        // ✅ success response
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                user_id: user.user_id,
                username: user.username,
                full_name: user.full_name,
                role: user.role,
                suspended: user.suspended
            }
        });

    } catch (err) {
        res.json({
            success: false,
            message: 'Server error: ' + err.message
        });
    }
});

module.exports = router;
