const express = require('express');
const router  = express.Router();
const db      = require('../db');

// Update username
router.post('/profile/update-username', async (req, res) => {
    const { old_username, new_username } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET username = ? WHERE username = ?',
            [new_username, old_username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Username updated' });
        } else {
            res.json({ status: 'error', message: 'User not found' });
        }
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.json({ status: 'error', message: 'Username already taken' });
        } else {
            res.json({ status: 'error', message: 'Server error: ' + err.message });
        }
    }
});

// Update PIN/password
router.post('/profile/update-pin', async (req, res) => {
    const { username, new_pin } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET password = ? WHERE username = ?',
            [new_pin, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'PIN updated' });
        } else {
            res.json({ status: 'error', message: 'User not found' });
        }
    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

// Update security question
router.post('/profile/update-security', async (req, res) => {
    const { username, security_question, security_answer } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET security_question = ?, security_answer = ? WHERE username = ?',
            [security_question, security_answer, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Security question updated' });
        } else {
            res.json({ status: 'error', message: 'User not found' });
        }
    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

// Update profile picture path
router.post('/profile/update-pic', async (req, res) => {
    const { username, profile_pic } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET profile_pic = ? WHERE username = ?',
            [profile_pic, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Profile picture updated' });
        } else {
            res.json({ status: 'error', message: 'User not found' });
        }
    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

module.exports = router;
