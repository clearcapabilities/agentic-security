const express = require('express');
const User = require('./model');
const app = express();

app.get('/profile/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  // VULNERABLE: res.send embeds the stored bio without escaping.
  res.send(`<html><body><h1>${user.name}</h1><div>${user.bio}</div></body></html>`);
});

app.listen(3001);
