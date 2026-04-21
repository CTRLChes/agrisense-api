require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const db      = require('./db');
const app     = express();

app.use(cors());
app.use(express.json());

// Auto-create tables on startup
async function initDB() {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        full_name VARCHAR(100),
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'general_user',
        security_question VARCHAR(255),
        security_answer VARCHAR(255),
        profile_pic VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.execute(`CREATE TABLE IF NOT EXISTS evaluations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        date VARCHAR(50) NOT NULL,
        nitrogen VARCHAR(50),
        phosphorus VARCHAR(50),
        potassium VARCHAR(50),
        moisture VARCHAR(50),
        soil_ph VARCHAR(50),
        recommended_crop VARCHAR(100),
        fertilizer VARCHAR(100),
        compatibility VARCHAR(50),
        latitude VARCHAR(50),
        longitude VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('Tables ready!');
}

initDB().catch(console.error);

// Routes
app.use('/api', require('./routes/register'));
app.use('/api', require('./routes/login'));
app.use('/api', require('./routes/evaluation'));
app.use('/api', require('./routes/profile'));

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Agrisense API running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
