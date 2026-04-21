require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const app        = express();

app.use(cors());
app.use(express.json());

// Routes
app.use('/api', require('./routes/register'));
app.use('/api', require('./routes/login'));

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Agrisense API running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));