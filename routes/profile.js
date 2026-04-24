const express = require('express');
const router  = express.Router();
const db      = require('../db');

// Get user role
router.get('/user/role/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const [rows] = await db.execute(
            'SELECT role FROM users WHERE username = ?',
            [username]
        );
        if (rows.length === 0) {
            return res.json({ status: 'error', message: 'User not found' });
        }
        res.json({ status: 'success', role: rows[0].role });
    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

// Get security question by username
router.get('/forgot/question/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const [rows] = await db.execute(
            'SELECT security_question FROM users WHERE username = ?',
            [username]
        );
        if (rows.length === 0 || !rows[0].security_question) {
            return res.json({ status: 'error', message: 'User not found' });
        }
        res.json({ status: 'success', security_question: rows[0].security_question });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
});

// Verify security answer
router.post('/forgot/verify-answer', async (req, res) => {
    const { username, answer } = req.body;
    try {
        const [rows] = await db.execute(
            'SELECT * FROM users WHERE username = ? AND security_answer = ?',
            [username, answer]
        );
        if (rows.length === 0) {
            return res.json({ status: 'error', message: 'Incorrect answer' });
        }
        res.json({ status: 'success', message: 'Answer correct' });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
});

// Reset PIN
// Reset PIN - in forgot password flow
router.post('/forgot/reset-pin', async (req, res) => {
    const { username, new_pin } = req.body;
    try {
        const hashed = await bcrypt.hash(new_pin, 10); // ✅ hash it!
        const [result] = await db.execute(
            'UPDATE users SET password = ? WHERE username = ?',
            [hashed, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'PIN reset successfully' });
        } else {
            res.json({ status: 'error', message: 'User not found' });
        }
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
});

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
