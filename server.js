'use strict';

const http = require('http');
const { spawn } = require('child_process');
const store = require('./server/store');
const { handleRequest } = require('./server/app');
const { PACKAGED } = require('./server/paths');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error('[security] ошибка обработки запроса:', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    }
    res.end(JSON.stringify({ error: 'internal_error' }));
  });
});

server.on('clientError', (err, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

async function main() {
  await store.init();
  server.listen(PORT, HOST, () => {
    const shown = HOST === '0.0.0.0' ? 'localhost' : HOST;
    console.log('');
    console.log('  ██  Security — защищённый мессенджер');
    console.log(`  ▸  Открыт:  http://${shown}:${PORT}`);
    console.log('  ▸  Бета-режим: код входа показывается прямо на экране');
    console.log('  ▸  Повторный вход защищён постоянным кодом доступа');
    console.log('  ▸  База данных зашифрована (AES-256-GCM)');
    console.log('');

    if (PACKAGED) {
      const url = `http://localhost:${PORT}`;
      try {
        spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
      } catch {
        /* не критично — откройте адрес вручную */
      }
    }
  });
}

main().catch((err) => {
  console.error('[security] не удалось запустить сервер:', err);
  process.exit(1);
});
