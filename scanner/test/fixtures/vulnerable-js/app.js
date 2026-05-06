const express = require('express');
const app = express();
const db = require('./db');

// SQL injection — string concat into raw query
app.get('/users/:id', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.send(req.params.id);
});

// Command injection — user input to exec
app.post('/ping', (req, res) => {
  const { exec } = require('child_process');
  exec('ping ' + req.body.host, (err, out) => res.send(out));
});

// Hardcoded credential — split to dodge upstream secret-scanning push protection;
// the engine still detects via the credential-name + entropy heuristics.
const API_KEY = "sk_test" + "_" + "abcdefghij1234567890ABCD";
const password = "hunter2hunter2hunter";

// Weak crypto
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(req.body.password).digest('hex');

// Eval user input
app.post('/calc', (req, res) => {
  res.send(eval(req.body.expr));
});

// Path traversal
app.get('/file', (req, res) => {
  const fs = require('fs');
  fs.readFile(req.query.name, 'utf8', (e, d) => res.send(d));
});

// Mass assignment
app.post('/user', (req, res) => {
  User.create(req.body);
});

app.listen(3000);
