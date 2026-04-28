require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt = require('bcryptjs');
const db      = require('./db');
const app     = express();

app.use(cors());
app.use(express.json());

/* ═══════════════════════════════════════════════════════════════
   AUTO-CREATE / MIGRATE TABLES ON STARTUP
   ═══════════════════════════════════════════════════════════════ */
async function initDB() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS users (
            user_id           INT AUTO_INCREMENT PRIMARY KEY,
            username          VARCHAR(100) NOT NULL UNIQUE,
            password          VARCHAR(255) NOT NULL,
            role              VARCHAR(50)  DEFAULT 'general_user',
            suspended         TINYINT(1)   NOT NULL DEFAULT 0,
            security_question VARCHAR(255),
            security_answer   VARCHAR(255),
            profile_pic       VARCHAR(500),
            created_at        TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    `);

    /* Migration: add `suspended` column if this is an existing DB that
       was created before this column existed.                           */
    try {
        await db.execute(`
            ALTER TABLE users ADD COLUMN suspended TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log('✅ Migrated: added suspended column to users');
    } catch (e) {
        /* Error 1060 = "Duplicate column name" — column already exists, ignore. */
        if (e.errno !== 1060) throw e;
    }

    await db.execute(`
        CREATE TABLE IF NOT EXISTS evaluations (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            username         VARCHAR(100) NOT NULL,
            date             VARCHAR(50)  NOT NULL,
            nitrogen         VARCHAR(50),
            phosphorus       VARCHAR(50),
            potassium        VARCHAR(50),
            moisture         VARCHAR(50),
            soil_ph          VARCHAR(50),
            recommended_crop VARCHAR(100),
            fertilizer       VARCHAR(100),
            compatibility    VARCHAR(50),
            latitude         VARCHAR(50),
            longitude        VARCHAR(50),
            archived         TINYINT(1)   NOT NULL DEFAULT 0,
            archived_at      TIMESTAMP    NULL DEFAULT NULL,
            created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    `);

    /* Migration: add archive columns to evaluations if they don't exist yet. */
    for (const colDef of [
        'archived    TINYINT(1) NOT NULL DEFAULT 0',
        'archived_at TIMESTAMP  NULL DEFAULT NULL'
    ]) {
        try {
            await db.execute(`ALTER TABLE evaluations ADD COLUMN ${colDef}`);
        } catch (e) {
            if (e.errno !== 1060) throw e;
        }
    }

    await db.execute(`
        CREATE TABLE IF NOT EXISTS crops (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(120) NOT NULL,
            type        VARCHAR(60),
            farm_price  DECIMAL(10,2) DEFAULT 0,
            mkt_price   DECIMAL(10,2) DEFAULT 0,
            unit        VARCHAR(30)   DEFAULT 'kg',
            season      VARCHAR(60),
            notes       TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    `);

    console.log('✅ Tables ready!');
}

initDB().catch(console.error);

/* ════════════════════════════════════════
   HEALTH CHECK
   ════════════════════════════════════════ */
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'AgriSense API running' });
});

/* ════════════════════════════════════════
   AUTH — REGISTER
   ════════════════════════════════════════ */
app.post('/api/register', async (req, res) => {
    const { username, security_question, security_answer } = req.body;
    const pin = req.body.pin || req.body.password;

    if (!username || !pin)
        return res.status(400).json({ status: 'error', message: 'Username and PIN are required.' });
    if (!/^\d{6}$/.test(pin))
        return res.status(400).json({ status: 'error', message: 'PIN must be exactly 6 digits.' });

    try {
        const [existing] = await db.query('SELECT user_id FROM users WHERE username = ?', [username]);
        if (existing.length)
            return res.status(409).json({ status: 'error', message: 'Username already taken.' });

        const hashed = await bcrypt.hash(pin, 10);
        await db.query(
            `INSERT INTO users (username, password, role, security_question, security_answer)
             VALUES (?, ?, 'general_user', ?, ?)`,
            [username, hashed, security_question || '', (security_answer || '').toLowerCase()]
        );
        res.status(201).json({ status: 'success', message: 'Account created successfully.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   AUTH — LOGIN
   Returns `suspended: true/false` so the
   frontend can block login immediately.
   ════════════════════════════════════════ */
app.post('/api/login', async (req, res) => {
    const { username } = req.body;
    const pin = req.body.pin || req.body.password;

    if (!username || !pin)
        return res.status(400).json({ status: 'error', message: 'Username and PIN are required.' });

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
        if (!rows.length)
            return res.status(401).json({ status: 'error', message: 'Username not found.' });

        const user  = rows[0];
        const match = await bcrypt.compare(String(pin), user.password);
        if (!match)
            return res.status(401).json({ status: 'error', message: 'Incorrect PIN.' });

        /* Block login for suspended accounts — return a clear error so the
           frontend shows the right message without a secondary API round-trip. */
        if (user.suspended) {
            return res.status(403).json({
                status:  'error',
                message: 'Your account has been suspended. Please contact an administrator.'
            });
        }

        res.json({
            status:    'success',
            message:   'Login successful.',
            user_id:   user.user_id,
            username:  user.username,
            full_name: user.username,
            role:      user.role || 'general_user',
            suspended: false
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   AUTH — FORGOT PIN (3-step)
   ════════════════════════════════════════ */
app.post('/api/forgot/lookup', async (req, res) => {
    const { username } = req.body;
    if (!username)
        return res.status(400).json({ status: 'error', message: 'Username is required.' });
    try {
        const [rows] = await db.query(
            'SELECT user_id, security_question FROM users WHERE username = ? LIMIT 1', [username]
        );
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'Username not found.' });
        res.json({ status: 'success', userId: rows[0].user_id, security_question: rows[0].security_question });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/forgot/verify', async (req, res) => {
    const { userId, answer } = req.body;
    if (!userId || !answer)
        return res.status(400).json({ status: 'error', message: 'User ID and answer are required.' });
    try {
        const [rows] = await db.query('SELECT security_answer FROM users WHERE user_id = ? LIMIT 1', [userId]);
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        if (rows[0].security_answer !== answer.toLowerCase())
            return res.status(401).json({ status: 'error', message: 'Incorrect answer. Please try again.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/forgot/reset', async (req, res) => {
    const { userId, pin } = req.body;
    if (!userId || !pin)
        return res.status(400).json({ status: 'error', message: 'User ID and new PIN are required.' });
    if (!/^\d{6}$/.test(pin))
        return res.status(400).json({ status: 'error', message: 'PIN must be exactly 6 digits.' });
    try {
        const [rows] = await db.query('SELECT user_id FROM users WHERE user_id = ? LIMIT 1', [userId]);
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        const hashed = await bcrypt.hash(pin, 10);
        await db.query('UPDATE users SET password = ? WHERE user_id = ?', [hashed, userId]);
        res.json({ status: 'success', message: 'PIN reset successfully.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   USERS — legacy CRUD  (kept for compat)
   ════════════════════════════════════════ */
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT user_id AS id, username, role, suspended,
                    security_question, profile_pic,
                    created_at AS createdAt
             FROM users ORDER BY created_at DESC`
        );
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.put('/api/users/:id', async (req, res) => {
    const { role, username } = req.body;
    const pin = req.body.pin || req.body.password;
    const fields = [], values = [];

    if (role     !== undefined) { fields.push('role = ?');     values.push(role); }
    if (username !== undefined) { fields.push('username = ?'); values.push(username); }
    if (pin      !== undefined) {
        if (!/^\d{6}$/.test(pin))
            return res.status(400).json({ status: 'error', message: 'PIN must be exactly 6 digits.' });
        const hashed = await bcrypt.hash(pin, 10);
        fields.push('password = ?'); values.push(hashed);
    }
    if (!fields.length)
        return res.status(400).json({ status: 'error', message: 'Nothing to update.' });
    try {
        const [result] = await db.query(
            `UPDATE users SET ${fields.join(', ')} WHERE user_id = ?`, [...values, req.params.id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const [result] = await db.query('DELETE FROM users WHERE user_id = ?', [req.params.id]);
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   ADMIN — USER MANAGEMENT
   These are the endpoints called by admin.php
   ════════════════════════════════════════ */

/* GET /api/admin/users
   Returns the full user list including the suspended flag.
   The frontend uses this to cross-check suspension on login
   and on every page load of app.php.                        */
app.get('/api/admin/users', async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT user_id, username, role, suspended,
                    security_question, profile_pic, created_at
             FROM users ORDER BY created_at DESC`
        );
        res.json({ status: 'success', users: rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/admin/suspend
   Body: { user_id, suspended }  (suspended = true | false)
   This is the authoritative server-side toggle; once set here
   the login endpoint will immediately block the suspended user. */
app.post('/api/admin/suspend', async (req, res) => {
    const { user_id, suspended } = req.body;
    if (user_id === undefined || suspended === undefined)
        return res.status(400).json({ status: 'error', message: 'user_id and suspended are required.' });

    const suspendedVal = suspended ? 1 : 0;
    try {
        const [result] = await db.query(
            'UPDATE users SET suspended = ? WHERE user_id = ?', [suspendedVal, user_id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({
            status:    'success',
            message:   suspended ? 'Account suspended.' : 'Account reactivated.',
            suspended: suspendedVal === 1
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/admin/update-role
   Body: { user_id, role }  */
app.post('/api/admin/update-role', async (req, res) => {
    const { user_id, role } = req.body;
    if (!user_id || !role)
        return res.status(400).json({ status: 'error', message: 'user_id and role are required.' });

    const allowed = ['general_user', 'General User', 'Contributor', 'Admin'];
    if (!allowed.includes(role))
        return res.status(400).json({ status: 'error', message: 'Invalid role value.' });

    try {
        const [result] = await db.query(
            'UPDATE users SET role = ? WHERE user_id = ?', [role, user_id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({ status: 'success', message: 'Role updated.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   PROFILE — self-service updates
   Called by admin.php's Manage User modal
   ════════════════════════════════════════ */

/* POST /api/profile/update-username
   Body: { old_username, new_username }  */
app.post('/api/profile/update-username', async (req, res) => {
    const { old_username, new_username } = req.body;
    if (!old_username || !new_username)
        return res.status(400).json({ status: 'error', message: 'old_username and new_username are required.' });
    if (old_username === new_username)
        return res.json({ status: 'success', message: 'No change.' });

    try {
        const [conflict] = await db.query(
            'SELECT user_id FROM users WHERE username = ? LIMIT 1', [new_username]
        );
        if (conflict.length)
            return res.status(409).json({ status: 'error', message: 'Username already taken.' });

        const [result] = await db.query(
            'UPDATE users SET username = ? WHERE username = ?', [new_username, old_username]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });

        res.json({ status: 'success', message: 'Username updated.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/profile/update-security
   Body: { username, security_question, security_answer }  */
app.post('/api/profile/update-security', async (req, res) => {
    const { username, security_question, security_answer } = req.body;
    if (!username || !security_question || !security_answer)
        return res.status(400).json({ status: 'error', message: 'username, security_question and security_answer are required.' });

    try {
        const [result] = await db.query(
            'UPDATE users SET security_question = ?, security_answer = ? WHERE username = ?',
            [security_question, security_answer.toLowerCase(), username]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({ status: 'success', message: 'Security Q&A updated.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/profile/update-pin
   Body: { username, new_pin }  */
app.post('/api/profile/update-pin', async (req, res) => {
    const { username, new_pin } = req.body;
    if (!username || !new_pin)
        return res.status(400).json({ status: 'error', message: 'username and new_pin are required.' });
    if (!/^\d{6}$/.test(new_pin))
        return res.status(400).json({ status: 'error', message: 'PIN must be exactly 6 digits.' });

    try {
        const [rows] = await db.query('SELECT user_id FROM users WHERE username = ? LIMIT 1', [username]);
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'User not found.' });

        const hashed = await bcrypt.hash(new_pin, 10);
        await db.query('UPDATE users SET password = ? WHERE username = ?', [hashed, username]);
        res.json({ status: 'success', message: 'PIN updated.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   EVALUATIONS — CRUD
   Includes soft-archive support.
   ════════════════════════════════════════ */

/* GET /api/evaluations — returns only non-archived rows */
app.get('/api/evaluations', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM evaluations WHERE archived = 0 ORDER BY created_at DESC'
        );
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/evaluations', async (req, res) => {
    const {
        username, date, nitrogen, phosphorus, potassium,
        moisture, soil_ph, recommended_crop, fertilizer,
        compatibility, latitude, longitude
    } = req.body;
    if (!username || !date)
        return res.status(400).json({ status: 'error', message: 'Username and date are required.' });
    try {
        await db.query(
            `INSERT INTO evaluations
             (username, date, nitrogen, phosphorus, potassium, moisture, soil_ph,
              recommended_crop, fertilizer, compatibility, latitude, longitude)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [username, date, nitrogen||'', phosphorus||'', potassium||'',
             moisture||'', soil_ph||'', recommended_crop||'',
             fertilizer||'', compatibility||'', latitude||'', longitude||'']
        );
        res.status(201).json({ status: 'success', message: 'Evaluation saved.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.delete('/api/evaluations/:id', async (req, res) => {
    try {
        const [result] = await db.query('DELETE FROM evaluations WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Evaluation not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/evaluations/:id/archive — soft-archive a single evaluation */
app.post('/api/evaluations/:id/archive', async (req, res) => {
    try {
        const [result] = await db.query(
            'UPDATE evaluations SET archived = 1, archived_at = NOW() WHERE id = ? AND archived = 0',
            [req.params.id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Evaluation not found or already archived.' });
        res.json({ status: 'success', message: 'Evaluation archived.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* POST /api/evaluations/:id/restore — restore an archived evaluation */
app.post('/api/evaluations/:id/restore', async (req, res) => {
    try {
        const [result] = await db.query(
            'UPDATE evaluations SET archived = 0, archived_at = NULL WHERE id = ? AND archived = 1',
            [req.params.id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Evaluation not found or not archived.' });
        res.json({ status: 'success', message: 'Evaluation restored.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* GET /api/evaluations/archived — returns only archived rows */
app.get('/api/evaluations/archived', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM evaluations WHERE archived = 1 ORDER BY archived_at DESC'
        );
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   CROPS — CRUD
   ════════════════════════════════════════ */
app.get('/api/crops', async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT id, name, type,
                    farm_price AS farmPrice, mkt_price AS mktPrice,
                    unit, season, notes,
                    created_at AS createdAt, updated_at AS updatedAt
             FROM crops ORDER BY updated_at DESC`
        );
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/crops', async (req, res) => {
    const { name, type, farmPrice, mktPrice, unit, season, notes } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    if (!type) return res.status(400).json({ status: 'error', message: 'Crop category is required.' });
    try {
        await db.query(
            `INSERT INTO crops (name, type, farm_price, mkt_price, unit, season, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, type, farmPrice||0, mktPrice||0, unit||'kg', season||'', notes||'']
        );
        res.status(201).json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.put('/api/crops/:id', async (req, res) => {
    const { name, type, farmPrice, mktPrice, unit, season, notes } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    try {
        const [result] = await db.query(
            `UPDATE crops SET name=?, type=?, farm_price=?, mkt_price=?,
             unit=?, season=?, notes=? WHERE id=?`,
            [name, type||'', farmPrice||0, mktPrice||0, unit||'kg', season||'', notes||'', req.params.id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Crop not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.delete('/api/crops/:id', async (req, res) => {
    try {
        const [result] = await db.query('DELETE FROM crops WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Crop not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   START
   ════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 AgriSense API running on port ${PORT}`));
