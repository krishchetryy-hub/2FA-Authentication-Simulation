CREATE DATABASE IF NOT EXISTS twofa_app;
USE twofa_app;
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    twofa_secret VARCHAR(255),
    is_twofa_enabled BOOLEAN DEFAULT FALSE
);
DESCRIBE users;
SELECT * FROM users;
UPDATE users 
SET is_twofa_enabled = FALSE, 
    twofa_secret = NULL 
WHERE email = 'krishchetry697@gmail.com';
SELECT email, is_twofa_enabled FROM users;
USE twofa_app;

UPDATE users 
SET is_twofa_enabled = 0,
    twofa_secret = NULL
WHERE email = 'krishchetry697@gmail.com';
SELECT email, is_twofa_enabled FROM users;
SHOW DATABASES;
SELECT id, email, is_twofa_enabled FROM users;
UPDATE users
SET is_twofa_enabled = 0,
    twofa_secret = NULL
WHERE id = 1;
SELECT id, email, is_twofa_enabled FROM users;
