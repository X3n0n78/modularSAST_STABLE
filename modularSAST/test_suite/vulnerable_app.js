/**
 * Vulnerable JavaScript application for testing ModularSAST
 * This file contains intentional security vulnerabilities for testing purposes
 */

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// XSS vulnerability - innerHTML
app.get('/xss1', (req, res) => {
    const userInput = req.query.name;
    // Vulnerable: directly setting innerHTML with user input
    const html = `<div id="content"></div>
    <script>
        document.getElementById('content').innerHTML = '${userInput}';
    </script>`;
    res.send(html);
});

// XSS vulnerability - document.write
app.get('/xss2', (req, res) => {
    const userInput = req.query.data;
    const html = `<script>document.write('${userInput}');</script>`;
    res.send(html);
});

// Code injection - eval
app.get('/eval', (req, res) => {
    const userCode = req.query.code;
    // Vulnerable: evaluating user-controlled code
    const result = eval(userCode);
    res.json({ result });
});

// Command injection - exec
app.get('/command', (req, res) => {
    const filename = req.query.file;
    // Vulnerable: executing user-controlled commands
    exec(`cat ${filename}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error.message);
            return;
        }
        res.send(stdout);
    });
});

// Path traversal - fs.readFile
app.get('/read', (req, res) => {
    const filepath = req.query.path;
    // Vulnerable: reading arbitrary files
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send(data);
    });
});

// SQL injection (simulated)
app.get('/user', (req, res) => {
    const userId = req.query.id;
    // Vulnerable: SQL injection via string concatenation
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    // db.query(query) would be vulnerable
    res.send(`Executing query: ${query}`);
});

// Weak cryptography
const crypto = require('crypto');

function weakHash(data) {
    // Vulnerable: using MD5 for hashing
    return crypto.createHash('md5').update(data).digest('hex');
}

function weakRandom() {
    // Vulnerable: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2, 15);
}

// Prototype pollution
app.post('/merge', (req, res) => {
    const userObject = req.body;
    const target = {};
    // Vulnerable: Object.assign with untrusted input
    Object.assign(target, userObject);
    res.json(target);
});

// Safe alternative (for comparison)
const DOMPurify = require('isomorphic-dompurify');

app.get('/safe-xss', (req, res) => {
    const userInput = req.query.name;
    // Safe: sanitized input
    const clean = DOMPurify.sanitize(userInput);
    res.send(`<div>${clean}</div>`);
});

app.listen(3000, () => {
    console.log('Vulnerable app listening on port 3000');
});

module.exports = app;
