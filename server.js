require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, 'public')));

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("MySQL Connected ✅");
    }
});

// Start Server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
// Register Route
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            [email, hashedPassword],
            (err, result) => {
                if (err) {
    console.log("INSERT ERROR:", err);  // 🔥 Add this line
    return res.send("Database error");
}
                res.send("Registration successful! Go to login page.");
            }
        );
    } catch (error) {
        res.send("Error during registration");
    }
});
// Login Route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, results) => {
            if (err) {
                console.log("LOGIN ERROR:", err);
                return res.send("Database error");
            }

            if (results.length === 0) {
                return res.send("User not found");
            }

            const user = results[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.send("Incorrect password");
            }

            req.session.user = user;

            // 🔥 ADD THIS CONDITION
            if (user.is_twofa_enabled) {
    res.redirect('/2fa/login');   // new route
} else {
    res.redirect('/2fa/setup');
}
        }
    );
});
// 2FA Login Page
app.get('/2fa/login', (req, res) => {

    if (!req.session.user) {
        return res.send("Please login first");
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Verify 2FA</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>

<div class="container">
    <h2>🔐 Enter OTP</h2>

    <form action="/verify" method="POST">
        <input type="text" name="token" placeholder="Enter 6-digit code" required />
        <button type="submit">Verify</button>
    </form>
</div>

</body>
</html>
`);
});
// 2FA Setup Route
app.get('/2fa/setup', async (req, res) => {

    if (!req.session.user) {
        return res.send("Please login first");
    }

    const secret = speakeasy.generateSecret({
        length: 20,
        name: `2FA-App (${req.session.user.email})`
    });

    db.query(
        "UPDATE users SET twofa_secret = ? WHERE id = ?",
        [secret.base32, req.session.user.id],
        async (err) => {
            if (err) {
                console.log("2FA SECRET SAVE ERROR:", err);
                return res.send("Error saving 2FA secret");
            }

            const qrCodeImage = await QRCode.toDataURL(secret.otpauth_url);

            res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Setup 2FA</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>

<div class="container">
    <h2>🔐 Setup Two-Factor Authentication</h2>
    <p>Scan this QR code using Google Authenticator</p>

    <img src="${qrCodeImage}" style="width:200px; margin:20px 0;" />

    <form action="/verify" method="POST">
        <input type="text" name="token" placeholder="Enter 6-digit code" required />
        <button type="submit">Verify & Activate</button>
    </form>
</div>

</body>
</html>
`);
        }
    );
});  
// 2FA Verify Route
app.post('/verify', (req, res) => {

    if (!req.session.user) {
        return res.send("Please login first");
    }

    const { token } = req.body;

    db.query(
        "SELECT twofa_secret FROM users WHERE id = ?",
        [req.session.user.id],
        (err, results) => {

            if (err) {
                console.log("VERIFY ERROR:", err);
                return res.send("Database error");
            }

            const secret = results[0].twofa_secret;

            const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 1   // 🔥 Allows ±30 seconds tolerance
});

            if (verified) {

    db.query(
        "UPDATE users SET is_twofa_enabled = TRUE WHERE id = ?",
        [req.session.user.id],
        (updateErr) => {
            if (updateErr) {
                console.log("2FA ENABLE ERROR:", updateErr);
                return res.send("Error enabling 2FA");
            }

            res.send("2FA Enabled Successfully 🎉 Secure Login Complete!");
        }
    );

} else {
    res.send("Invalid OTP ❌");
}
        }
    );
});