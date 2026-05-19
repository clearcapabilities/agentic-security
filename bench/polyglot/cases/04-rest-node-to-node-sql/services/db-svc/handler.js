const express = require('express');
const db = require('./db');
const app = express();
app.use(express.json());

app.post('/users/lookup', async (req, res) => {
  // VULNERABLE: SQL injection — body.name concatenated into raw SQL.
  const rows = await db.query("SELECT id, name FROM users WHERE name = '" + req.body.name + "'");
  res.json(rows);
});

app.listen(4000);
