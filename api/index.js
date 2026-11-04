'use strict';

module.exports = (req, res) => {
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({
    url: req.url,
    method: req.method,
    query: req.query || null,
    headers: {
      host: req.headers.host,
      'x-forwarded-host': req.headers['x-forwarded-host'],
      'x-vercel-id': req.headers['x-vercel-id'],
      'x-matched-path': req.headers['x-matched-path'],
    },
    bodyType: typeof req.body,
    bodyIsBuffer: Buffer.isBuffer(req.body),
    body: req.body && !Buffer.isBuffer(req.body) ? req.body : null,
  }));
};
