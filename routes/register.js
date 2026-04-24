const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const db      = require('../db');

router.post('/register', async (req, res) => {
    const { 
        username, 
        email, 
        password, 
        full_name,
        security_question,
        security_answer
    } = req.body;

    if (!username || !password) {
        return res.json({ 
            status: 'error', 
            message: 'Username and password are required' 
        });
    }

    if (password.length < 4) {
        return res.json({ 
            status: 'error', 
            message: 'Password must be at least 4 characters' 
        });
    }

    try {
        const hashed = await bcrypt.hash(password, 10);

        await db.execute(
            `INSERT INTO users 
                (username, email, full_name, password, role, security_question, security_answer) 
             VALUES (?, ?, ?, ?, 'general_user', ?, ?)`,
            [
                username, 
                email || username + '@agrisense.com', 
                full_name || username, 
                hashed,
                security_question || null,
                security_answer || null
            ]
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
