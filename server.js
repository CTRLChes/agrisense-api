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

/* HEALTH CHECK */
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'AgriSense API running' });
});

/* REGISTER */
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

/* LOGIN */
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

/* EVALUATION GET BY USER (FIXED) */
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
            `SELECT * FROM evaluations WHERE username = ? ORDER BY ${orderBy}`,
            [username]
        );

        res.json({ status: 'success', data: rows });

    } catch (e) {
        console.error(e);
        res.status(500).json({ status: 'error', message: e.message });
    }
});

/* START */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 AgriSense API running on port ${PORT}`));
