'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');
const readline = require('readline');
const { db, save, FILES_DIR, AVATARS_DIR } = require('./store');
const { ROOT, PUBLIC_DIR, PACKAGED } = require('./paths');
const realtime = require('./realtime');

db.accessChallenges = db.accessChallenges || {};

const JSON_LIMIT = 512 * 1024;
const FILE_LIMIT = 32 * 1024 * 1024;
const AVATAR_LIMIT = 2 * 1024 * 1024;
const CODE_TTL_MS = 5 * 60 * 1000;
const CODE_RESEND_MS = 45 * 1000;
const ACCESS_TTL_MS = 5 * 60 * 1000;
const ACCESS_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/* --------------------------- конфигурация приложения ---------------------- */

// Настройки можно задать переменными окружения или файлом security.config.json
// рядом с server.js / .exe. Это удобно для собранного релиза.
let fileConfig = {};
try {
  fileConfig = JSON.parse(fs.readFileSync(path.join(ROOT, 'security.config.json'), 'utf8'));
} catch {
  fileConfig = {};
}

function cfg(envName, fileKey, fallback) {
  if (process.env[envName] !== undefined && process.env[envName] !== '') return process.env[envName];
  if (fileConfig[fileKey] !== undefined && fileConfig[fileKey] !== '') return fileConfig[fileKey];
  return fallback;
}

// Бета-режим: код входа показывается прямо на экране и не отправляется наружу.
// Это удобно без настроенного Gmail/SMS, но любой, кто знает номер/адрес,
// может получить код. Для реального использования выключите betaMode.
const BETA_MODE = String(cfg('BETA_MODE', 'betaMode', 'true')).toLowerCase() === 'true';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
};

/* ------------------------------- утилиты ------------------------------- */

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendError(res, status, error, extra = {}) {
  sendJson(res, status, { error, ...extra });
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error('too_large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const buf = await readBody(req, JSON_LIMIT);
  if (!buf.length) return {};
  try {
    const parsed = JSON.parse(buf.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('bad');
    return parsed;
  } catch {
    throw Object.assign(new Error('bad_json'), { status: 400 });
  }
}

function id(prefix) {
  return prefix + crypto.randomBytes(10).toString('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function lookupMime(buf) {
  if (!buf || buf.length < 4) return null;
  const header = buf.slice(0, 16);
  // JPEG: FF D8 FF
  if (header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff) return 'image/jpeg';
  // PNG: 89 50 4E 47
  if (header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4e && header[3] === 0x47) return 'image/png';
  // WebP: RIFF .... WEBP
  if (
    header[0] === 0x52 &&
    header[1] === 0x49 &&
    header[2] === 0x46 &&
    header[3] === 0x46 &&
    header[8] === 0x57 &&
    header[9] === 0x45 &&
    header[10] === 0x42 &&
    header[11] === 0x50
  ) {
    return 'image/webp';
  }
  // GIF: GIF87a / GIF89a
  if (header[0] === 0x47 && header[1] === 0x49 && header[2] === 0x46) return 'image/gif';
  return null;
}

function nowIso() {
  return new Date().toISOString();
}

function normalizePhone(raw) {
  let digits = String(raw || '').replace(/\D/g, '');
  if (digits.length === 11 && digits.startsWith('8')) digits = '7' + digits.slice(1);
  if (digits.length === 10) digits = '7' + digits;
  if (digits.length < 10 || digits.length > 15) return null;
  return digits;
}

function normalizeEmail(raw) {
  const email = String(raw || '').trim().toLowerCase();
  if (email.length < 6 || email.length > 254) return null;
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(email)) {
    return null;
  }
  return email;
}

// Определяет, что ввёл пользователь: телефон или e-mail.
function parseIdentifier(raw) {
  const value = String(raw || '').trim();
  if (value.includes('@')) {
    const email = normalizeEmail(value);
    return email ? { kind: 'email', value: email } : null;
  }
  const phone = normalizePhone(value);
  return phone ? { kind: 'phone', value: phone } : null;
}

function maskEmail(email) {
  const [name, domain] = String(email).split('@');
  if (!domain) return email;
  const visible = name.slice(0, Math.min(2, name.length));
  return `${visible}${'•'.repeat(Math.max(1, name.length - visible.length))}@${domain}`;
}

function formatPhone(phone) {
  if (!phone) return '';
  if (phone.startsWith('7') && phone.length === 11) {
    return `+7 ${phone.slice(1, 4)} ${phone.slice(4, 7)}-${phone.slice(7, 9)}-${phone.slice(9)}`;
  }
  return '+' + phone;
}

function generateAccessCode() {
  let raw = '';
  for (let i = 0; i < 8; i += 1) {
    raw += ACCESS_ALPHABET[crypto.randomInt(0, ACCESS_ALPHABET.length)];
  }
  return raw;
}

function formatAccessCode(code) {
  const raw = String(code || '').toUpperCase();
  return raw.length === 8 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;
}

function normalizeAccessCode(raw) {
  return String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
}

/* --------------------------- отправка письма (SMTP) ------------------------ */

function smtpSend({ host, port, user, pass, fromAddress, fromName, to, subject, text }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: true },
      () => {},
    );
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* ignore */ }
      reject(err);
    };
    socket.setTimeout(25000, () => fail(new Error('smtp_timeout')));
    socket.on('error', fail);

    const rl = readline.createInterface({ input: socket, crlfDelay: Infinity });
    const iterator = rl[Symbol.asyncIterator]();

    async function readResponse() {
      const first = await iterator.next();
      if (first.done) throw new Error('smtp_closed');
      let line = String(first.value);
      let code = line.slice(0, 3);
      let full = line;
      while (line.length > 3 && line[3] === '-') {
        const next = await iterator.next();
        if (next.done) throw new Error('smtp_closed');
        line = String(next.value);
        full += '\n' + line;
      }
      return { code, text: full };
    }

    const write = (line) => socket.write(line + '\r\n');

    (async () => {
      let r = await readResponse();
      if (!r.code.startsWith('2')) throw new Error(`smtp_greeting: ${r.text}`);

      write('EHLO security.local');
      r = await readResponse();
      if (!r.code.startsWith('2')) throw new Error(`smtp_ehlo: ${r.text}`);

      write('AUTH LOGIN');
      r = await readResponse();
      if (r.code !== '334') throw new Error(`smtp_auth: ${r.text}`);

      write(Buffer.from(user, 'utf8').toString('base64'));
      r = await readResponse();
      if (r.code !== '334') throw new Error(`smtp_auth_user: ${r.text}`);

      write(Buffer.from(pass, 'utf8').toString('base64'));
      r = await readResponse();
      if (r.code !== '235') throw new Error(`smtp_auth_pass: ${r.text}`);

      write(`MAIL FROM:<${fromAddress}>`);
      r = await readResponse();
      if (!r.code.startsWith('2')) throw new Error(`smtp_mail_from: ${r.text}`);

      write(`RCPT TO:<${to}>`);
      r = await readResponse();
      if (!r.code.startsWith('2')) throw new Error(`smtp_rcpt_to: ${r.text}`);

      write('DATA');
      r = await readResponse();
      if (r.code !== '354') throw new Error(`smtp_data: ${r.text}`);

      const body = Buffer.from(text, 'utf8')
        .toString('base64')
        .replace(/.{1,76}/g, '$&\r\n');
      const headers = [
        `From: =?UTF-8?B?${Buffer.from(fromName, 'utf8').toString('base64')}?= <${fromAddress}>`,
        `To: <${to}>`,
        `Subject: =?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: base64',
        `Date: ${new Date().toUTCString()}`,
      ].join('\r\n');

      socket.write(`${headers}\r\n\r\n${body}\r\n.\r\n`);
      r = await readResponse();
      if (!r.code.startsWith('2')) throw new Error(`smtp_send: ${r.text}`);

      write('QUIT');
      try { await readResponse(); } catch { /* сервер может закрыть соединение */ }

      settled = true;
      socket.end();
      resolve(true);
    })().catch(fail);
  });
}

// Отправляет код на e-mail через Gmail SMTP (или другой SMTP-сервер).
async function sendEmailCode(email, code) {
  const host = String(cfg('SMTP_HOST', 'smtpHost', 'smtp.gmail.com'));
  const port = Number(cfg('SMTP_PORT', 'smtpPort', 465)) || 465;
  const user = String(cfg('SMTP_USER', 'smtpUser', ''));
  const pass = String(cfg('SMTP_PASS', 'smtpPass', '')).replace(/\s+/g, '');
  const fromName = String(cfg('SMTP_FROM_NAME', 'smtpFromName', cfg('APP_NAME', 'appName', 'Security')));
  const appName = String(cfg('APP_NAME', 'appName', 'Security'));

  if (!user || !pass) {
    console.error('[email] SMTP не настроен: задайте SMTP_USER и SMTP_PASS (пароль приложения Gmail)');
    return { sent: false };
  }

  try {
    await smtpSend({
      host,
      port,
      user,
      pass,
      fromAddress: user,
      fromName,
      to: email,
      subject: `Код подтверждения в ${appName}`,
      text:
        `Ваш код подтверждения в ${appName}: ${code}\n\n` +
        'Код действует 5 минут. Если вы не запрашивали вход, просто проигнорируйте письмо.',
    });
    console.log(`[email] код отправлен на ${maskEmail(email)}`);
    return { sent: true };
  } catch (err) {
    console.error('[email] не удалось отправить письмо:', err.message);
    return { sent: false };
  }
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function issueSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha256(token)] = { userId: user.id, createdAt: nowIso(), lastSeenAt: nowIso() };
  save();
  return token;
}

/* -------------------------------- модели ------------------------------- */

function publicUser(user) {
  if (!user) return null;
  let avatarUrl = null;
  if (user.avatar && user.avatar.updatedAt) {
    avatarUrl = `/api/avatar/${user.id}?t=${encodeURIComponent(String(user.avatar.updatedAt))}`;
  }
  return {
    id: user.id,
    phone: user.phone || null,
    email: user.email || null,
    name: user.name,
    avatarUrl,
    publicKey: user.publicKey || null,
    keysUpdatedAt: user.keysUpdatedAt || null,
    createdAt: user.createdAt,
    online: realtime.isOnline(user.id),
    lastSeenAt: user.lastSeenAt || null,
  };
}

function publicMessage(message) {
  return {
    id: message.id,
    chatId: message.chatId,
    senderId: message.senderId,
    kind: message.kind,
    fileId: message.fileId || null,
    payload: message.payload,
    clientId: message.clientId || null,
    createdAt: message.createdAt,
  };
}

function chatOf(chatId) {
  return db.chats[chatId] || null;
}

function isMember(chat, userId) {
  return !!chat && chat.members.includes(userId);
}

function findChat(a, b) {
  const key = [a, b].sort().join('|');
  return Object.values(db.chats).find((chat) => chat.membersKey === key) || null;
}

function ensureChat(a, b) {
  const existing = findChat(a, b);
  if (existing) return existing;
  const chat = {
    id: id('c_'),
    members: [a, b],
    membersKey: [a, b].sort().join('|'),
    createdAt: nowIso(),
    lastMessageAt: null,
    lastRead: {},
  };
  db.chats[chat.id] = chat;
  db.messages[chat.id] = [];
  save();
  return chat;
}

function serializeChat(chat, viewerId) {
  const peerId = chat.members.find((member) => member !== viewerId);
  const peer = db.users[peerId] || null;
  const messages = db.messages[chat.id] || [];
  const last = messages.length ? messages[messages.length - 1] : null;
  const myRead = chat.lastRead[viewerId] || null;
  let unread = 0;
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message.senderId === viewerId) continue;
    if (myRead && message.createdAt <= myRead) break;
    unread += 1;
  }
  return {
    id: chat.id,
    peer: publicUser(peer),
    peerLastRead: peerId ? chat.lastRead[peerId] || null : null,
    myLastRead: myRead,
    lastMessage: last ? publicMessage(last) : null,
    unread,
    createdAt: chat.createdAt,
    lastMessageAt: chat.lastMessageAt,
  };
}

function peerIdsOf(userId) {
  const ids = [];
  for (const chat of Object.values(db.chats)) {
    if (!chat.members.includes(userId)) continue;
    for (const member of chat.members) if (member !== userId) ids.push(member);
  }
  return Array.from(new Set(ids));
}

function sessionUser(req, url) {
  let token = '';
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) token = header.slice(7).trim();
  if (!token && url) token = url.searchParams.get('token') || '';
  if (!token) return null;
  const session = db.sessions[sha256(token)];
  if (!session) return null;
  const user = db.users[session.userId];
  if (!user) return null;
  session.lastSeenAt = nowIso();
  user.lastSeenAt = session.lastSeenAt;
  return user;
}

/* ----------------------------- присутствие ----------------------------- */

realtime.subscribePresence((userId, online) => {
  const peers = peerIdsOf(userId);
  if (!peers.length) return;
  realtime.sendAll(peers, 'presence', { userId, online, at: nowIso() });
});

/* -------------------------------- роутер ------------------------------- */

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return sendError(res, 400, 'bad_path');
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');

  if (pathname.startsWith('/api/')) {
    try {
      return await handleApi(req, res, url, pathname);
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) console.error('[api]', pathname, err);
      return sendError(res, status, err.status ? err.message : 'internal_error');
    }
  }

  return serveStatic(req, res, pathname);
}

async function handleApi(req, res, url, pathname) {
  const method = req.method.toUpperCase();

  /* ---------- авторизация ---------- */

  if (pathname === '/api/auth/start' && method === 'POST') {
    const body = await readJson(req);
    const ident = parseIdentifier(body.identifier || body.phone || body.email);
    if (!ident) return sendError(res, 400, 'bad_identifier');

    const key = ident.value;
    const formatted = ident.kind === 'phone' ? formatPhone(key) : maskEmail(key);
    const existing = db.codes[key];
    const now = Date.now();
    if (existing && now - existing.sentAt < CODE_RESEND_MS && !existing.used) {
      // Код уже создан недавно. Не раскрываем его повторно, кроме бета-режима.
      return sendJson(res, 200, {
        ok: true,
        kind: ident.kind,
        identifier: key,
        formatted,
        sent: true,
        beta: BETA_MODE,
        ...(BETA_MODE ? { betaCode: existing.code } : {}),
        expiresIn: Math.max(0, Math.floor((existing.expiresAt - now) / 1000)),
        reused: true,
      });
    }

    // Без бета-режима телефонный вход отключён: код уходит только на Gmail.
    if (!BETA_MODE && ident.kind !== 'email') {
      return sendError(res, 403, 'phone_beta_only', {
        hint: 'Вход по телефону доступен только в бета-режиме. Используйте Gmail.',
      });
    }

    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');

    if (!BETA_MODE) {
      const result = await sendEmailCode(key, code);
      if (!result.sent) {
        // Не сохраняем код, который никуда не ушёл.
        delete db.codes[key];
        save();
        return sendError(res, 503, 'email_not_configured', {
          hint: 'Настройте SMTP_USER и SMTP_PASS (пароль приложения Gmail) в security.config.json',
        });
      }
    }

    // В бета-режиме код сохраняется и показывается на экране.
    const sentAt = Date.now();
    db.codes[key] = {
      code,
      kind: ident.kind,
      expiresAt: sentAt + CODE_TTL_MS,
      sentAt,
      attempts: 0,
      used: false,
    };
    save();

    return sendJson(res, 200, {
      ok: true,
      kind: ident.kind,
      identifier: key,
      formatted,
      sent: true,
      beta: BETA_MODE,
      ...(BETA_MODE ? { betaCode: code } : {}),
      expiresIn: Math.floor(CODE_TTL_MS / 1000),
    });
  }

  if (pathname === '/api/auth/verify' && method === 'POST') {
    const body = await readJson(req);
    const ident = parseIdentifier(body.identifier || body.phone || body.email);
    const code = String(body.code || '').replace(/\D/g, '');
    if (!ident) return sendError(res, 400, 'bad_identifier');
    if (code.length !== 6) return sendError(res, 400, 'bad_code');

    const key = ident.value;
    const entry = db.codes[key];
    if (!entry) return sendError(res, 400, 'code_not_requested');
    if (Date.now() > entry.expiresAt) {
      delete db.codes[key];
      save();
      return sendError(res, 400, 'code_expired');
    }
    if (entry.attempts >= 5) return sendError(res, 429, 'too_many_attempts');
    if (!safeEqual(entry.code, code)) {
      entry.attempts += 1;
      save();
      return sendError(res, 400, 'wrong_code', { attemptsLeft: Math.max(0, 5 - entry.attempts) });
    }

    entry.used = true;
    delete db.codes[key];

    let user = ident.kind === 'phone'
      ? Object.values(db.users).find((item) => item.phone === key)
      : Object.values(db.users).find((item) => item.email === key);
    let isNew = false;
    if (!user) {
      isNew = true;
      const customName = String(body.name || '').trim();
      user = ident.kind === 'phone'
        ? {
            id: id('u_'),
            phone: key,
            email: null,
            name: customName || `Пользователь ${key.slice(-4)}`,
            publicKey: null,
            keysUpdatedAt: null,
            createdAt: nowIso(),
            lastSeenAt: nowIso(),
          }
        : {
            id: id('u_'),
            phone: null,
            email: key,
            name: customName || key.split('@')[0],
            publicKey: null,
            keysUpdatedAt: null,
            createdAt: nowIso(),
            lastSeenAt: nowIso(),
          };
      db.users[user.id] = user;
    }

    // Первый вход (или старый аккаунт без кода): создаём код доступа
    // и показываем его пользователю один раз.
    let newAccessCode = null;
    if (!user.accessCode) {
      user.accessCode = generateAccessCode();
      user.accessCodeUpdatedAt = nowIso();
      newAccessCode = user.accessCode;
    }

    // Повторный вход: без кода доступа сессия не выдаётся.
    if (user.accessCode && !newAccessCode) {
      const challenge = crypto.randomBytes(24).toString('hex');
      db.accessChallenges[sha256(challenge)] = {
        userId: user.id,
        expiresAt: Date.now() + ACCESS_TTL_MS,
        attempts: 0,
        createdAt: nowIso(),
      };
      save();
      return sendJson(res, 200, {
        ok: true,
        accessRequired: true,
        challenge,
        identifier: key,
        kind: ident.kind,
        formatted: ident.kind === 'phone' ? formatPhone(key) : maskEmail(key),
      });
    }

    const token = issueSession(user);
    return sendJson(res, 200, {
      ok: true,
      token,
      user: publicUser(user),
      isNew,
      ...(newAccessCode ? { accessCode: newAccessCode } : {}),
    });
  }

  if (pathname === '/api/auth/access' && method === 'POST') {
    const body = await readJson(req);
    const challenge = String(body.challenge || '').trim();
    const code = normalizeAccessCode(body.code);
    if (!challenge || code.length !== 8) return sendError(res, 400, 'bad_access_code');

    const key = sha256(challenge);
    const entry = db.accessChallenges[key];
    if (!entry) return sendError(res, 400, 'access_expired');
    if (Date.now() > entry.expiresAt) {
      delete db.accessChallenges[key];
      save();
      return sendError(res, 400, 'access_expired');
    }
    if (entry.attempts >= 5) return sendError(res, 429, 'too_many_access_attempts');

    const user = db.users[entry.userId];
    if (!user || !user.accessCode) {
      delete db.accessChallenges[key];
      save();
      return sendError(res, 400, 'access_expired');
    }
    if (!safeEqual(user.accessCode, code)) {
      entry.attempts += 1;
      save();
      return sendError(res, 400, 'wrong_access_code', {
        attemptsLeft: Math.max(0, 5 - entry.attempts),
      });
    }

    delete db.accessChallenges[key];
    const token = issueSession(user);
    return sendJson(res, 200, { ok: true, token, user: publicUser(user), isNew: false });
  }

  /* ---------- конфигурация приложения (без токена) ---------- */

  if (pathname === '/api/config' && method === 'GET') {
    return sendJson(res, 200, {
      appName: String(cfg('APP_NAME', 'appName', 'Security')),
      authMode: 'both',
      betaMode: BETA_MODE,
    });
  }

  /* ---------- дальше — только с токеном ---------- */

  const me = sessionUser(req, url);
  if (!me) return sendError(res, 401, 'unauthorized');

  if (pathname === '/api/me' && method === 'GET') {
    return sendJson(res, 200, { user: publicUser(me) });
  }

  if (pathname === '/api/me/security' && method === 'GET') {
    if (!me.accessCode) {
      me.accessCode = generateAccessCode();
      me.accessCodeUpdatedAt = nowIso();
      save();
    }
    return sendJson(res, 200, {
      accessCode: formatAccessCode(me.accessCode),
      identifier: me.email || me.phone || null,
      updatedAt: me.accessCodeUpdatedAt || null,
    });
  }

  if (pathname === '/api/me/access-code/rotate' && method === 'POST') {
    me.accessCode = generateAccessCode();
    me.accessCodeUpdatedAt = nowIso();
    // Все ожидающие входы по старому коду становятся недействительными.
    for (const [key, value] of Object.entries(db.accessChallenges)) {
      if (value.userId === me.id) delete db.accessChallenges[key];
    }
    save();
    return sendJson(res, 200, {
      ok: true,
      accessCode: formatAccessCode(me.accessCode),
      updatedAt: me.accessCodeUpdatedAt,
    });
  }

  if (pathname === '/api/me' && (method === 'PATCH' || method === 'PUT')) {
    const body = await readJson(req);
    const previousName = me.name;
    if (typeof body.name === 'string') {
      const name = body.name.trim().slice(0, 64);
      if (name) me.name = name;
    }
    save();
    if (me.name !== previousName) {
      realtime.sendAll(peerIdsOf(me.id), 'profile', { user: publicUser(me) });
    }
    return sendJson(res, 200, { ok: true, user: publicUser(me) });
  }

  if (pathname === '/api/me/avatar' && method === 'POST') {
    const buf = await readBody(req, AVATAR_LIMIT);
    if (!buf.length) return sendError(res, 400, 'empty_file');

    // Проверяем, что это изображение.
    const mime = lookupMime(buf);
    if (!mime || !mime.startsWith('image/')) {
      return sendError(res, 400, 'not_image');
    }

    const filePath = path.join(AVATARS_DIR, `${me.id}.bin`);
    await fs.promises.writeFile(filePath, buf);

    const now = nowIso();
    me.avatar = { mime, size: buf.length, updatedAt: now };
    me.updatedAt = now;
    save();

    realtime.sendAll(peerIdsOf(me.id), 'profile', { user: publicUser(me) });
    return sendJson(res, 200, { ok: true, user: publicUser(me) });
  }

  if (pathname === '/api/avatar/:id' || /^\/api\/avatar\/[^/]+$/.test(pathname)) {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed');
    const match = pathname.match(/^\/api\/avatar\/([^/]+)$/);
    if (!match) return sendError(res, 404, 'not_found');
    const userId = match[1];
    const user = db.users[userId];
    if (!user || !user.avatar) return sendError(res, 404, 'avatar_not_found');
    const filePath = path.join(AVATARS_DIR, `${userId}.bin`);
    let data;
    try {
      data = await fs.promises.readFile(filePath);
    } catch {
      return sendError(res, 404, 'avatar_missing');
    }
    res.writeHead(200, {
      'Content-Type': user.avatar.mime,
      'Content-Length': data.length,
      'Cache-Control': 'private, max-age=31536000, immutable',
    });
    return res.end(data);
  }

  if (pathname === '/api/me/keys' && method === 'PUT') {
    const body = await readJson(req);
    const key = typeof body.publicKey === 'string' ? body.publicKey.trim() : '';
    if (!/^[A-Za-z0-9+/=]{40,200}$/.test(key)) return sendError(res, 400, 'bad_key');
    const hadKey = !!me.publicKey;
    const changed = hadKey && me.publicKey !== key;
    me.publicKey = key;
    me.keysUpdatedAt = nowIso();
    save();
    if (changed || !hadKey) {
      realtime.sendAll(peerIdsOf(me.id), 'keychange', {
        userId: me.id,
        first: !hadKey,
        at: me.keysUpdatedAt,
      });
    }
    return sendJson(res, 200, { ok: true, user: publicUser(me) });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (token) delete db.sessions[sha256(token)];
    save();
    return sendJson(res, 200, { ok: true });
  }

  /* ---------- поиск людей ---------- */

  if (pathname === '/api/contacts/lookup' && method === 'GET') {
    const raw = url.searchParams.get('query')
      || url.searchParams.get('phone')
      || url.searchParams.get('email')
      || '';
    const ident = parseIdentifier(raw);
    if (!ident) return sendError(res, 400, 'bad_identifier');
    const user = Object.values(db.users).find((item) =>
      ident.kind === 'phone' ? item.phone === ident.value : item.email === ident.value,
    );
    if (!user) return sendError(res, 404, 'user_not_found');
    if (user.id === me.id) return sendError(res, 400, 'self');
    return sendJson(res, 200, { user: publicUser(user) });
  }

  if (pathname === '/api/contacts' && method === 'GET') {
    const users = Object.values(db.users)
      .filter((user) => user.id !== me.id)
      .map(publicUser);
    return sendJson(res, 200, { users });
  }

  /* ---------- чаты ---------- */

  if (pathname === '/api/chats' && method === 'GET') {
    const chats = Object.values(db.chats)
      .filter((chat) => chat.members.includes(me.id))
      .map((chat) => serializeChat(chat, me.id))
      .sort((a, b) => {
        const at = a.lastMessageAt || a.createdAt;
        const bt = b.lastMessageAt || b.createdAt;
        return bt.localeCompare(at);
      });
    return sendJson(res, 200, { chats });
  }

  if (pathname === '/api/chats' && method === 'POST') {
    const body = await readJson(req);
    const peer = db.users[body.peerId];
    if (!peer) return sendError(res, 404, 'peer_not_found');
    if (peer.id === me.id) return sendError(res, 400, 'self');
    const chat = ensureChat(me.id, peer.id);
    return sendJson(res, 200, { chat: serializeChat(chat, me.id) });
  }

  const chatMessagesMatch = pathname.match(/^\/api\/chats\/([^/]+)\/messages$/);
  if (chatMessagesMatch) {
    const chat = chatOf(chatMessagesMatch[1]);
    if (!isMember(chat, me.id)) return sendError(res, 404, 'chat_not_found');

    if (method === 'GET') {
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit') || 60)));
      const before = url.searchParams.get('before');
      const all = db.messages[chat.id] || [];
      let pool = all;
      if (before) pool = all.filter((message) => message.createdAt < before);
      const slice = pool.slice(-limit);
      return sendJson(res, 200, {
        messages: slice.map(publicMessage),
        hasMore: pool.length > slice.length,
      });
    }

    if (method === 'POST') {
      const body = await readJson(req);
      const kind = String(body.kind || 'text');
      if (!['text', 'file', 'voice'].includes(kind)) return sendError(res, 400, 'bad_kind');
      const payload = body.payload;
      if (!payload || typeof payload !== 'object' || !payload.forPeer || !payload.forSelf) {
        return sendError(res, 400, 'bad_payload');
      }
      if (JSON.stringify(payload).length > 256 * 1024) return sendError(res, 413, 'payload_too_large');

      let fileId = null;
      if (body.fileId) {
        const file = db.files[body.fileId];
        if (!file || file.ownerId !== me.id) return sendError(res, 400, 'bad_file');
        file.chatId = chat.id;
        fileId = file.id;
      }

      const message = {
        id: id('m_'),
        chatId: chat.id,
        senderId: me.id,
        kind,
        fileId,
        payload,
        clientId: body.clientId ? String(body.clientId).slice(0, 64) : null,
        createdAt: nowIso(),
      };
      if (!db.messages[chat.id]) db.messages[chat.id] = [];
      db.messages[chat.id].push(message);
      chat.lastMessageAt = message.createdAt;
      save();

      const wire = publicMessage(message);
      realtime.sendAll(chat.members, 'message', { message: wire });
      return sendJson(res, 200, { message: wire, chat: serializeChat(chat, me.id) });
    }
  }

  const chatReadMatch = pathname.match(/^\/api\/chats\/([^/]+)\/read$/);
  if (chatReadMatch && method === 'POST') {
    const chat = chatOf(chatReadMatch[1]);
    if (!isMember(chat, me.id)) return sendError(res, 404, 'chat_not_found');
    const body = await readJson(req);
    const upTo = body.upTo && typeof body.upTo === 'string' ? body.upTo : nowIso();
    if (!chat.lastRead[me.id] || chat.lastRead[me.id] < upTo) chat.lastRead[me.id] = upTo;
    save();
    realtime.sendAll(
      chat.members.filter((member) => member !== me.id),
      'read',
      { chatId: chat.id, userId: me.id, upTo: chat.lastRead[me.id] },
    );
    return sendJson(res, 200, { ok: true, upTo: chat.lastRead[me.id] });
  }

  const chatTypingMatch = pathname.match(/^\/api\/chats\/([^/]+)\/typing$/);
  if (chatTypingMatch && method === 'POST') {
    const chat = chatOf(chatTypingMatch[1]);
    if (!isMember(chat, me.id)) return sendError(res, 404, 'chat_not_found');
    realtime.sendAll(
      chat.members.filter((member) => member !== me.id),
      'typing',
      { chatId: chat.id, userId: me.id, at: nowIso() },
    );
    return sendJson(res, 200, { ok: true });
  }

  /* ---------- файлы ---------- */

  if (pathname === '/api/files' && method === 'POST') {
    const buf = await readBody(req, FILE_LIMIT);
    if (!buf.length) return sendError(res, 400, 'empty_file');
    const fileId = id('f_');
    const filePath = path.join(FILES_DIR, `${fileId}.bin`);
    await fs.promises.writeFile(filePath, buf);
    db.files[fileId] = {
      id: fileId,
      ownerId: me.id,
      chatId: null,
      size: buf.length,
      createdAt: nowIso(),
    };
    save();
    return sendJson(res, 200, { fileId, size: buf.length });
  }

  const fileMatch = pathname.match(/^\/api\/files\/([^/]+)$/);
  if (fileMatch && method === 'GET') {
    const file = db.files[fileMatch[1]];
    if (!file) return sendError(res, 404, 'file_not_found');
    const allowed =
      file.ownerId === me.id || (file.chatId && isMember(chatOf(file.chatId), me.id));
    if (!allowed) return sendError(res, 403, 'forbidden');
    const filePath = path.join(FILES_DIR, `${file.id}.bin`);
    let data;
    try {
      data = await fs.promises.readFile(filePath);
    } catch {
      return sendError(res, 404, 'file_missing');
    }
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': data.length,
      'Cache-Control': 'private, max-age=31536000, immutable',
    });
    return res.end(data);
  }

  /* ---------- звонки (сигнализация) ---------- */

  if (pathname === '/api/calls/signal' && method === 'POST') {
    const body = await readJson(req);
    const target = db.users[body.to];
    if (!target) return sendError(res, 404, 'peer_not_found');
    if (!findChat(me.id, target.id)) return sendError(res, 403, 'no_chat');
    const call = body.call;
    if (!call || typeof call !== 'object' || !['offer', 'answer', 'ice', 'end', 'reject', 'busy'].includes(call.type)) {
      return sendError(res, 400, 'bad_call');
    }
    const delivered = realtime.send(target.id, 'call', {
      from: publicUser(me),
      call,
      at: nowIso(),
    });
    return sendJson(res, 200, { ok: true, delivered: delivered > 0 });
  }

  /* ---------- поток событий ---------- */

  if (pathname === '/api/events' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write('retry: 2000\n\n');
    res.write(`event: ready\ndata: ${JSON.stringify({ userId: me.id, online: realtime.onlineUsers() })}\n\n`);

    const detach = realtime.add(me.id, res);

    // Приветственное присутствие для собеседников
    realtime.sendAll(peerIdsOf(me.id), 'presence', { userId: me.id, online: true, at: nowIso() });

    const close = () => {
      detach();
      try {
        res.end();
      } catch {
        /* уже закрыт */
      }
    };
    req.on('close', close);
    req.on('error', close);
    return undefined;
  }

  return sendError(res, 404, 'not_found');
}

/* ------------------------------ статика ------------------------------- */

async function serveStatic(req, res, pathname) {
  const method = req.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return sendError(res, 405, 'method_not_allowed');

  let relative = pathname === '/' ? '/index.html' : pathname;
  let filePath = path.join(PUBLIC_DIR, relative);
  if (!filePath.startsWith(PUBLIC_DIR)) return sendError(res, 403, 'forbidden');

  let stat = null;
  try {
    stat = await fs.promises.stat(filePath);
  } catch {
    stat = null;
  }

  if (!stat || stat.isDirectory()) {
    if (path.extname(pathname)) return sendError(res, 404, 'not_found');
    filePath = path.join(PUBLIC_DIR, 'index.html');
    try {
      stat = await fs.promises.stat(filePath);
    } catch {
      return sendError(res, 404, 'not_found');
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  const type = MIME_TYPES[ext] || 'application/octet-stream';
  res.writeHead(200, {
    'Content-Type': type,
    'Content-Length': stat.size,
    'Cache-Control': 'no-cache',
  });
  if (method === 'HEAD') return res.end();
  fs.createReadStream(filePath).pipe(res);
  return undefined;
}

module.exports = { handleRequest };
