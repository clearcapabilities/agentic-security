const express = require('express');
const app = express();
app.use(express.json());

// Edge service: receives the search request and forwards to the DB-svc.
app.post('/api/search', async (req, res) => {
  const name = req.body.name;
  const r = await fetch('http://db-svc:4000/users/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  const data = await r.json();
  res.json(data);
});

app.listen(3000);
