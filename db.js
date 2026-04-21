const mysql = require('mysql2');

const pool = mysql.createPool({
    host:            process.env.DB_HOST,
    user:            process.env.DB_USER,
    password:        process.env.DB_PASS,
    database:        process.env.DB_NAME,
    port:            process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false
    },
    connectTimeout:     30000,
    waitForConnections: true,
    connectionLimit:    10,
    queueLimit:         0
});

// Test connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('DB Connection Error:', err.message);
    } else {
        console.log('DB Connected successfully!');
        connection.release();
    }
});

module.exports = pool.promise();
