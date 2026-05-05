require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
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

    /* Migration: add suspended column if this is an existing DB */
    try {
        await db.execute(`
            ALTER TABLE users ADD COLUMN suspended TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log('✅ Migrated: added suspended column to users');
    } catch (e) {
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
            fertilizer_rate        VARCHAR(100),
            fertilizer_timing      VARCHAR(100),
            fertilizer_application VARCHAR(100),
            archived         TINYINT(1)   NOT NULL DEFAULT 0,
            archived_at      TIMESTAMP    NULL DEFAULT NULL,
            created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    `);

    /* Migration: add archive columns */
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

    /* Migration: add fertilizer columns */
    for (const colDef of [
        'fertilizer_rate        VARCHAR(100)',
        'fertilizer_timing      VARCHAR(100)',
        'fertilizer_application VARCHAR(100)'
    ]) {
        try {
            await db.execute(`ALTER TABLE evaluations ADD COLUMN ${colDef}`);
            console.log(`✅ Added column: ${colDef.split(' ')[0]}`);
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
            rt_note     TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    `);

    /* Migration: add rt_note column if missing */
    try {
        await db.execute(`ALTER TABLE crops ADD COLUMN rt_note TEXT`);
        console.log('✅ Migrated: added rt_note column to crops');
    } catch (e) {
        if (e.errno !== 1060) throw e;
    }

    /* Price history table */
    await db.execute(`
        CREATE TABLE IF NOT EXISTS crop_price_history (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            crop_id      INT NOT NULL,
            crop_name    VARCHAR(120) NOT NULL,
            farm_price   DECIMAL(10,2),
            mkt_price    DECIMAL(10,2),
            recorded_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_crop_id (crop_id),
            INDEX idx_recorded_at (recorded_at)
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
   AI PROXY — Malita, Davao Occidental crop price fetch
   Keeps the API key server-side only.
   POST /api/ai/prices  { crops: ["Rice", "Corn", ...] }
   ════════════════════════════════════════ */
app.post('/api/ai/prices', async (req, res) => {
    const { crops } = req.body;
    if (!Array.isArray(crops) || crops.length === 0)
        return res.status(400).json({ status: 'error', message: 'crops array is required.' });

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey)
        return res.status(500).json({ status: 'error', message: 'ANTHROPIC_API_KEY is not configured on the server.' });

    const nameList = crops.join(', ');

    // ── Malita-specific prompt ──────────────────────────────────────────────
    const prompt =
        `You are an agricultural pricing expert specializing in Malita, Davao Occidental, Philippines. ` +
        `Provide the LATEST farm-gate price and retail/market price in Philippine Pesos (₱) per kilogram ` +
        `for these crops as traded in Malita and the surrounding Davao Occidental area, ` +
        `reflecting current prices based on DA-XI (Department of Agriculture Region XI), ` +
        `PSA (Philippine Statistics Authority), and Malita LGU/municipal market data: ${nameList}.\n\n` +
        `Return ONLY a valid JSON object with NO markdown, NO explanation, NO extra text. Format:\n` +
        `{"CropName":{"farmgate":number,"retail":number,"unit":"kg","season":"year-round","note":"brief note"}}\n` +
        `Use the EXACT crop names I provided as keys. Use realistic current Philippine peso values ` +
        `appropriate for Malita, Davao Occidental local market conditions.`;
    // ───────────────────────────────────────────────────────────────────────

    try {
        const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type':      'application/json',
                'x-api-key':         apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model:      'claude-sonnet-4-20250514',
                max_tokens: 4096,
                messages:   [{ role: 'user', content: prompt }]
            })
        });

        if (!aiRes.ok) {
            const errText = await aiRes.text();
            console.error('Anthropic API error:', aiRes.status, errText);
            return res.status(502).json({ status: 'error', message: `Anthropic API error ${aiRes.status}` });
        }

        const data  = await aiRes.json();
        const text  = (data.content || []).map(b => b.text || '').join('');
        const clean = text.replace(/```json|```/g, '').trim();

        let parsed;
        try {
            parsed = JSON.parse(clean);
        } catch (parseErr) {
            console.error('Failed to parse AI response:', clean);
            return res.status(502).json({ status: 'error', message: 'AI returned invalid JSON.' });
        }

        res.json({ status: 'success', prices: parsed });
    } catch (e) {
        console.error('AI proxy error:', e);
        res.status(500).json({ status: 'error', message: e.message });
    }
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
   USER ROLE - Get user role
   ════════════════════════════════════════ */
app.get('/api/user/role/:username', async (req, res) => {
    const { username } = req.params;
    if (!username)
        return res.status(400).json({ status: 'error', message: 'Username is required.' });

    try {
        const [rows] = await db.query(
            'SELECT role FROM users WHERE username = ? LIMIT 1', [username]
        );
        if (rows.length === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });

        res.json({ status: 'success', role: rows[0].role || 'General User' });
    } catch (err) {
        console.error('Error fetching user role:', err);
        res.status(500).json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

/* ════════════════════════════════════════
   USER SECURITY - Get security question and answer
   ════════════════════════════════════════ */
app.get('/api/user/security/:username', async (req, res) => {
    const { username } = req.params;
    if (!username)
        return res.status(400).json({ status: 'error', message: 'Username is required.' });

    try {
        const [rows] = await db.query(
            'SELECT security_question, security_answer FROM users WHERE username = ? LIMIT 1', [username]
        );
        if (rows.length === 0)
            return res.status(404).json({ status: 'error', message: 'User not found.' });

        res.json({
            status:            'success',
            security_question: rows[0].security_question || '',
            security_answer:   rows[0].security_answer   || ''
        });
    } catch (err) {
        console.error('Error fetching user security:', err);
        res.status(500).json({ status: 'error', message: 'Server error: ' + err.message });
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
   USERS — legacy CRUD
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
   ════════════════════════════════════════ */
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
   ════════════════════════════════════════ */
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
   ════════════════════════════════════════ */
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

/* POST /api/evaluations — WITH fertilizer details */
app.post('/api/evaluations', async (req, res) => {
    const {
        username, date, nitrogen, phosphorus, potassium,
        moisture, soil_ph, recommended_crop, fertilizer,
        compatibility, latitude, longitude,
        fertilizer_rate, fertilizer_timing, fertilizer_application
    } = req.body;

    if (!username || !date)
        return res.status(400).json({ status: 'error', message: 'Username and date are required.' });

    try {
        await db.query(
            `INSERT INTO evaluations
             (username, date, nitrogen, phosphorus, potassium, moisture, soil_ph,
              recommended_crop, fertilizer, compatibility, latitude, longitude,
              fertilizer_rate, fertilizer_timing, fertilizer_application)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                username, date,
                nitrogen || '', phosphorus || '', potassium || '',
                moisture || '', soil_ph || '', recommended_crop || '',
                fertilizer || '', compatibility || '', latitude || '', longitude || '',
                fertilizer_rate || '', fertilizer_timing || '', fertilizer_application || ''
            ]
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
                    unit, season, notes, rt_note AS rtNote,
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
    const { name, type, farmPrice, mktPrice, unit, season, notes, rtNote } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    if (!type) return res.status(400).json({ status: 'error', message: 'Crop category is required.' });
    try {
        await db.query(
            `INSERT INTO crops (name, type, farm_price, mkt_price, unit, season, notes, rt_note)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, type, farmPrice || 0, mktPrice || 0, unit || 'kg', season || '', notes || '', rtNote || '']
        );
        res.status(201).json({ status: 'success' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.put('/api/crops/:id', async (req, res) => {
    const { name, type, farmPrice, mktPrice, unit, season, notes, rtNote } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    try {
        const [result] = await db.query(
            `UPDATE crops SET name=?, type=?, farm_price=?, mkt_price=?,
             unit=?, season=?, notes=?, rt_note=?, updated_at=NOW() WHERE id=?`,
            [name, type || '', farmPrice || 0, mktPrice || 0, unit || 'kg', season || '', notes || '', rtNote || '', req.params.id]
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
   CROPS — BULK UPSERT
   ════════════════════════════════════════ */
app.post('/api/crops/bulk-upsert', async (req, res) => {
    const { crops } = req.body;
    if (!Array.isArray(crops) || crops.length === 0)
        return res.status(400).json({ status: 'error', message: 'crops array is required.' });

    try {
        let inserted = 0, updated = 0, unchanged = 0;

        for (const c of crops) {
            if (!c.name) continue;
            const fp = parseFloat(c.farmPrice) || 0;
            const mp = parseFloat(c.mktPrice)  || 0;

            const [existing] = await db.query(
                'SELECT id, farm_price, mkt_price FROM crops WHERE LOWER(name) = LOWER(?) LIMIT 1',
                [c.name]
            );

            if (existing.length === 0) {
                const [ins] = await db.query(
                    `INSERT INTO crops (name, type, farm_price, mkt_price, unit, season, notes, rt_note)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [c.name, c.type || 'other', fp, mp, c.unit || 'kg', c.season || '', c.notes || '', c.rtNote || '']
                );
                await db.query(
                    `INSERT INTO crop_price_history (crop_id, crop_name, farm_price, mkt_price)
                     VALUES (?, ?, ?, ?)`,
                    [ins.insertId, c.name, fp, mp]
                );
                inserted++;
            } else {
                const row   = existing[0];
                const oldFp = parseFloat(row.farm_price);
                const oldMp = parseFloat(row.mkt_price);
                const priceChanged = Math.abs(oldFp - fp) > 0.01 || Math.abs(oldMp - mp) > 0.01;

                await db.query(
                    `UPDATE crops SET type=?, farm_price=?, mkt_price=?, unit=?, season=?, rt_note=?, updated_at=NOW()
                     WHERE id=?`,
                    [c.type || 'other', fp, mp, c.unit || 'kg', c.season || '', c.rtNote || '', row.id]
                );

                if (priceChanged) {
                    await db.query(
                        `INSERT INTO crop_price_history (crop_id, crop_name, farm_price, mkt_price)
                         VALUES (?, ?, ?, ?)`,
                        [row.id, c.name, fp, mp]
                    );
                    updated++;
                } else {
                    unchanged++;
                }
            }
        }

        res.json({ status: 'success', inserted, updated, unchanged });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* GET /api/crops/price-history */
app.get('/api/crops/price-history', async (req, res) => {
    const { cropId, limit } = req.query;
    try {
        let rows;
        if (cropId) {
            [rows] = await db.query(
                `SELECT * FROM crop_price_history WHERE crop_id = ?
                 ORDER BY recorded_at DESC LIMIT ?`,
                [parseInt(cropId), parseInt(limit) || 20]
            );
        } else {
            [rows] = await db.query(
                `SELECT h.* FROM crop_price_history h
                 INNER JOIN (
                   SELECT crop_id, MAX(recorded_at) AS latest FROM crop_price_history GROUP BY crop_id
                 ) latest ON h.crop_id = latest.crop_id AND h.recorded_at = latest.latest
                 ORDER BY h.recorded_at DESC LIMIT ?`,
                [parseInt(limit) || 100]
            );
        }
        res.json(rows);
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
