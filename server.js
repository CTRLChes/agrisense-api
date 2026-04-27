require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const db      = require('./db');
const app     = express();

app.use(cors());
app.use(express.json());

/* ═══════════════════════════════════════════════════════════════
   AUTO-CREATE TABLES ON STARTUP
   ═══════════════════════════════════════════════════════════════ */
async function initDB() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS users (
            user_id           INT AUTO_INCREMENT PRIMARY KEY,
            username          VARCHAR(100) NOT NULL UNIQUE,
            password          VARCHAR(255) NOT NULL,
            role              VARCHAR(50)  DEFAULT 'General User',
            security_question VARCHAR(255),
            security_answer   VARCHAR(255),
            profile_pic       VARCHAR(500),
            created_at        TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    `);

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
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

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
    if (pin.length < 4)
        return res.status(400).json({ status: 'error', message: 'PIN must be at least 4 digits.' });

    try {
        const [existing] = await db.execute('SELECT user_id FROM users WHERE username = ?', [username]);
        if (existing.length)
            return res.status(409).json({ status: 'error', message: 'Username already taken.' });

        const hashed = await bcrypt.hash(pin, 10);
        await db.execute(
            `INSERT INTO users (username, password, role, security_question, security_answer)
             VALUES (?, ?, 'General User', ?, ?)`,
            [username, hashed, security_question || '', security_answer || '']
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
        const [rows] = await db.execute('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
        if (!rows.length)
            return res.status(401).json({ status: 'error', message: 'Username not found.' });

        const user  = rows[0];
        const match = await bcrypt.compare(String(pin), user.password);
        if (!match)
            return res.status(401).json({ status: 'error', message: 'Incorrect PIN.' });

        res.json({
            status:   'success',
            message:  'Login successful.',
            user_id:  user.user_id,
            username: user.username,
            role:     user.role || 'General User'
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   FORGOT PIN
   ════════════════════════════════════════ */
app.post('/api/forgot/lookup', async (req, res) => {
    const { username } = req.body;
    if (!username)
        return res.status(400).json({ status: 'error', message: 'Username is required.' });
    try {
        const [rows] = await db.execute(
            'SELECT user_id, security_question FROM users WHERE username = ? LIMIT 1', [username]
        );
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'Username not found.' });
        res.json({
            status: 'success',
            userId: rows[0].user_id,
            security_question: rows[0].security_question
        });
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
        const [rows] = await db.execute(
            'SELECT security_answer FROM users WHERE user_id = ? LIMIT 1', [userId]
        );
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        if (rows[0].security_answer.toLowerCase() !== answer.toLowerCase())
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
    try {
        const hashed = await bcrypt.hash(pin, 10);
        await db.execute('UPDATE users SET password = ? WHERE user_id = ?', [hashed, userId]);
        res.json({ status: 'success', message: 'PIN reset successfully.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   USER ROLE
   ════════════════════════════════════════ */
app.get('/api/user/role/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const [rows] = await db.execute('SELECT role FROM users WHERE username = ?', [username]);
        if (!rows.length)
            return res.status(404).json({ status: 'error', message: 'User not found.' });
        res.json({ status: 'success', role: rows[0].role });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   ADMIN — USERS
   ════════════════════════════════════════ */
app.get('/api/admin/users', async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT user_id, username, role, created_at FROM users ORDER BY created_at DESC'
        );
        res.json({ status: 'success', users: rows });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/admin/update-role', async (req, res) => {
    const { user_id, role } = req.body;
    if (!['General User', 'Contributor'].includes(role))
        return res.status(400).json({ status: 'error', message: 'Invalid role.' });
    try {
        await db.execute('UPDATE users SET role = ? WHERE user_id = ?', [role, user_id]);
        res.json({ status: 'success', message: 'Role updated.' });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   EVALUATIONS
   ════════════════════════════════════════ */
app.get('/api/evaluations', async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT * FROM evaluations ORDER BY created_at DESC');
        res.json(rows);
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/evaluation/save', async (req, res) => {
    const {
        username, date, nitrogen, phosphorus, potassium,
        moisture, soil_ph, recommended_crop, fertilizer,
        compatibility, latitude, longitude
    } = req.body;
    if (!username || !date)
        return res.status(400).json({ status: 'error', message: 'Username and date are required.' });
    try {
        await db.execute(
            `INSERT INTO evaluations
             (username, date, nitrogen, phosphorus, potassium, moisture, soil_ph,
              recommended_crop, fertilizer, compatibility, latitude, longitude)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                username, date, nitrogen || '', phosphorus || '',
                potassium || '', moisture || '', soil_ph || '',
                recommended_crop || '', fertilizer || '',
                compatibility || '', latitude || '', longitude || ''
            ]
        );
        res.status(201).json({ status: 'success', message: 'Evaluation saved.' });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.get('/api/evaluation/:username', async (req, res) => {
    const { username } = req.params;
    const { sort }     = req.query;
    let orderBy;
    switch (sort) {
        case 'oldest':        orderBy = 'id ASC'; break;
        case 'compatibility': orderBy = 'CAST(REPLACE(compatibility, "%", "") AS UNSIGNED) DESC'; break;
        case 'crop':          orderBy = 'recommended_crop ASC'; break;
        default:              orderBy = 'id DESC';
    }
    try {
        const [rows] = await db.execute(
            SELECT * FROM evaluations WHERE username = ? ORDER BY ${orderBy},
            [username]
        );
        res.json({ status: 'success', data: rows });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   PROFILE
   ════════════════════════════════════════ */
app.post('/api/profile/update-username', async (req, res) => {
    const { old_username, new_username } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET username = ? WHERE username = ?',
            [new_username, old_username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Username updated.' });
        } else {
            res.json({ status: 'error', message: 'User not found.' });
        }
    } catch (e) {
        if (e.code === 'ER_DUP_ENTRY') {
            res.json({ status: 'error', message: 'Username already taken.' });
        } else {
            res.status(500).json({ status: 'error', message: e.message });
        }
    }
});

app.post('/api/profile/update-pin', async (req, res) => {
    const { username, new_pin } = req.body;
    try {
        const hashed = await bcrypt.hash(new_pin, 10);
        const [result] = await db.execute(
            'UPDATE users SET password = ? WHERE username = ?',
            [hashed, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'PIN updated.' });
        } else {
            res.json({ status: 'error', message: 'User not found.' });
        }
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/profile/update-security', async (req, res) => {
    const { username, security_question, security_answer } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET security_question = ?, security_answer = ? WHERE username = ?',
            [security_question, security_answer, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Security question updated.' });
        } else {
            res.json({ status: 'error', message: 'User not found.' });
        }
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/profile/update-pic', async (req, res) => {
    const { username, profile_pic } = req.body;
    try {
        const [result] = await db.execute(
            'UPDATE users SET profile_pic = ? WHERE username = ?',
            [profile_pic, username]
        );
        if (result.affectedRows > 0) {
            res.json({ status: 'success', message: 'Profile picture updated.' });
        } else {
            res.json({ status: 'error', message: 'User not found.' });
        }
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   CROPS
   ════════════════════════════════════════ */
app.get('/api/crops', async (req, res) => {
    try {
        const [rows] = await db.execute(
            `SELECT id, name, type,
                    farm_price AS farmPrice, mkt_price AS mktPrice,
                    unit, season, notes,
                    created_at AS createdAt, updated_at AS updatedAt
             FROM crops ORDER BY updated_at DESC`
        );
        res.json(rows);
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.post('/api/crops', async (req, res) => {
    const { name, type, farmPrice, mktPrice, unit, season, notes } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    if (!type) return res.status(400).json({ status: 'error', message: 'Crop category is required.' });
    try {
        await db.execute(
            `INSERT INTO crops (name, type, farm_price, mkt_price, unit, season, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, type, farmPrice || 0, mktPrice || 0, unit || 'kg', season || '', notes || '']
        );
        res.status(201).json({ status: 'success' });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.put('/api/crops/:id', async (req, res) => {
    const { name, type, farmPrice, mktPrice, unit, season, notes } = req.body;
    if (!name) return res.status(400).json({ status: 'error', message: 'Crop name is required.' });
    try {
        const [result] = await db.execute(
            `UPDATE crops SET name=?, type=?, farm_price=?, mkt_price=?,
             unit=?, season=?, notes=? WHERE id=?`,
            [name, type || '', farmPrice || 0, mktPrice || 0,
             unit || 'kg', season || '', notes || '', req.params.id]
        );
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Crop not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

app.delete('/api/crops/:id', async (req, res) => {
    try {
        const [result] = await db.execute('DELETE FROM crops WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0)
            return res.status(404).json({ status: 'error', message: 'Crop not found.' });
        res.json({ status: 'success' });
    } catch (e) {
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* ════════════════════════════════════════
   START
   ════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(🚀 AgriSense API running on port ${PORT}));
