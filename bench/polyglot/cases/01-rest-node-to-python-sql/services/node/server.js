const express = require('express');
const app = express();
app.use(express.json());

// Entry point: receives a search request from the frontend.
app.post('/search', async (req, res) => {
  const name = req.body.name;
  // Forward to the Python service — the boundary that the polyglot bench
  // should detect via the OpenAPI definition in ../../openapi.yaml.
  const r = await fetch('http://python-svc:5000/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  const data = await r.json();
  res.json(data);
});

app.listen(3000);
