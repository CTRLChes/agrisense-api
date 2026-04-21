const express = require('express');
const router  = express.Router();
const db      = require('../db');

// Save evaluation
router.post('/evaluation/save', async (req, res) => {
    const {
        username, date, nitrogen, phosphorus, potassium,
        moisture, soil_ph, recommended_crop, fertilizer,
        compatibility, latitude, longitude
    } = req.body;

    if (!username || !date) {
        return res.json({ status: 'error', message: 'Username and date are required' });
    }

    try {
        await db.execute(
            `INSERT INTO evaluations 
                (username, date, nitrogen, phosphorus, potassium, moisture, 
                 soil_ph, recommended_crop, fertilizer, compatibility, latitude, longitude)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [username, date, nitrogen, phosphorus, potassium,
             moisture, soil_ph, recommended_crop, fertilizer,
             compatibility, latitude, longitude]
        );

        res.json({ status: 'success', message: 'Evaluation saved successfully' });

    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

// Get all evaluations for a user
router.get('/evaluation/:username', async (req, res) => {
    const { username } = req.params;
    const { sort }     = req.query; // ?sort=newest|oldest|compatibility|crop

    let orderBy;
    switch (sort) {
        case 'oldest':        orderBy = 'id ASC';  break;
        case 'compatibility': orderBy = 'CAST(REPLACE(compatibility, "%", "") AS UNSIGNED) DESC'; break;
        case 'crop':          orderBy = 'recommended_crop ASC'; break;
        default:              orderBy = 'id DESC'; // newest
    }

    try {
        const [rows] = await db.execute(
            `SELECT * FROM evaluations WHERE username = ? ORDER BY ${orderBy}`,
            [username]
        );

        res.json({ status: 'success', data: rows });

    } catch (err) {
        res.json({ status: 'error', message: 'Server error: ' + err.message });
    }
});

module.exports = router;
