'use strict';
// Partner telemetry ingest: partners POST brotli-compressed JSON batches. Public endpoint, no auth on /ingest.
const express = require('express');
const zlib = require('node:zlib');

const app = express();
app.use(express.raw({ type: '*/*', limit: '20mb' }));

app.post('/ingest', (req, res) => {
  let body = req.body;
  if (req.get('content-encoding') === 'br') {
    // decompress whatever the client sent with the runtime's bundled Brotli decoder
    body = zlib.brotliDecompressSync(body);
  }
  const events = JSON.parse(body.toString('utf8'));
  res.json({ accepted: Array.isArray(events) ? events.length : 1 });
});

app.get('/healthz', (_req, res) => res.send('ok'));
app.listen(process.env.PORT || 8080);
