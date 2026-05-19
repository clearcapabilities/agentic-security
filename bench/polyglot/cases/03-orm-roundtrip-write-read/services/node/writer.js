const express = require('express');
const User = require('./model');
const app = express();
app.use(express.json());

app.put('/profile/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);   // VULNERABLE: mass assignment
  await user.save();
  res.json(user);
});

app.listen(3000);
