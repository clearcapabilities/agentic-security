// Genuine MongoDB query with user-controlled $where operator. SHOULD trigger.
const express = require('express');
const app = express();
const User = require('./model');

app.post('/find', async (req, res) => {
  const result = await User.find({ $where: req.body.q });
  res.json(result);
});

app.post('/lookup', async (req, res) => {
  const data = await User.findOne({ $or: [{ name: req.body.name }, { email: req.body.email }] });
  res.json(data);
});
