'use strict';

const store = require('../server/store');
const { handleRequest } = require('../server/app');

/**
 * Vercel перенаправляет все /api/* на эту функцию через vercel.json.
 * Исходный путь приходит в __path, исходный query сохраняется рядом.
 */
function restorePath(req) {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/api/index') return;
  const sub = url.searchParams.get('__path');
  if (!sub) return;
  url.searchParams.delete('__path');
  const query = url.searchParams.toString();
  req.url = `/api/${sub.replace(/^\/+/, '')}${query ? `?${query}` : ''}`;
}

function requestPath(req) {
  return new URL(req.url, 'http://localhost').pathname;
}

function isMutation(req) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return true;
  // Этот GET при отсутствии кода создаёт и сохраняет постоянный код доступа.
  return requestPath(req) === '/api/me/security';
}

function toBuffer(chunk) {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  return Buffer.from(String(chunk), 'utf8');
}

/**
 * Мутации сначала выполняются в «буфер ответа», затем состояние сохраняется
 * в Turso и только после успешной записи ответ уходит клиенту. Иначе при
 * конфликте блокировки клиент получил бы «успех», а данные потерялись бы.
 */
function createCaptureResponse() {
  const headers = {};
  const chunks = [];
  let status = 200;
  let finished = false;

  const setHeaders = (source) => {
    if (!source || typeof source !== 'object') return;
    for (const [name, value] of Object.entries(source)) {
      headers[String(name).toLowerCase()] = value;
    }
  };

  const res = {
    headersSent: false,
    writableEnded: false,
    setHeader(name, value) {
      headers[String(name).toLowerCase()] = value;
    },
    getHeader(name) {
      return headers[String(name).toLowerCase()];
    },
    removeHeader(name) {
      delete headers[String(name).toLowerCase()];
    },
    writeHead(code, statusMessageOrHeaders, maybeHeaders) {
      status = Number(code) || 200;
      if (typeof statusMessageOrHeaders === 'object') setHeaders(statusMessageOrHeaders);
      if (typeof maybeHeaders === 'object') setHeaders(maybeHeaders);
      res.headersSent = true;
      return res;
    },
    write(chunk) {
      if (chunk !== undefined && chunk !== null) chunks.push(toBuffer(chunk));
      return true;
    },
    end(chunk) {
      if (chunk !== undefined && chunk !== null) chunks.push(toBuffer(chunk));
      finished = true;
      res.headersSent = true;
      res.writableEnded = true;
      return res;
    },
    destroy() {},
    on() {
      return res;
    },
    once() {
      return res;
    },
    emit() {
      return false;
    },
  };

  return {
    res,
    headers,
    body: () => Buffer.concat(chunks),
    status: () => status,
    finished: () => finished,
  };
}

module.exports = async (req, res) => {
  restorePath(req);

  try {
    await store.init();
  } catch (err) {
    console.error('[vercel] store init:', err);
    if (!res.headersSent) {
      res.writeHead(503, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({ error: 'storage_unavailable' }));
    }
    return;
  }

  try {
    if (isMutation(req)) {
      const captured = createCaptureResponse();
      await store.withLock(async () => {
        await handleRequest(req, captured.res);
        if (!captured.finished()) {
          throw Object.assign(new Error('handler_not_finished'), { status: 500 });
        }
      });
      res.writeHead(captured.status(), captured.headers);
      res.end(captured.body());
      return;
    }

    await store.refresh();
    await handleRequest(req, res);
    if (store.hasChanges()) await store.flush();
  } catch (err) {
    console.error('[vercel] request:', requestPath(req), err);
    if (!res.headersSent) {
      const status = err.status || 500;
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({ error: err.userMessage || (status === 503 ? 'busy' : 'internal_error') }));
    } else {
      try {
        res.end();
      } catch {
        /* ответ уже закрыт */
      }
    }
  }
};
